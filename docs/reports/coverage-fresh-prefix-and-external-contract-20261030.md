# Instrumented fresh prefix, original-vs-fresh coverage, and the external comparison contract — 2026-10-30

Scope: the three declared-IRQ F5 runs under
`research/input-strategy-audit-20261027/runs/declared-irq-f5-20261030/`
(`wb-timer`, `apb-spi`, `ahb-sha`) and the previously measured `wb-timer` CPU
side.  This record adds the two things the earlier packages could not publish:

1. an **instrumented replay of the runs' own fresh prefixes**, so each measured
   scope has a second, genuinely instrumented covered/total; and
2. a **genuine original-vs-fresh coverage comparison** under
   `dut-line-block/offline-recorded-prefix.v1`, plus the **external same-budget
   comparison harness** (strict schema + validator + synthetic self-tests).

Coverage is still Verilator line/block instrumentation replayed offline from the
recorded command prefix.  Four instrumented builds were made, **one at a time**,
each under `flock /tmp/myfuzz-native.lock` with `--build-jobs 4` and
`--max-commands 2048`; no fuzz campaign, no native harness session and no DUT
search were started.  The three declared run directories and the earlier CPU
measurement were not modified; every new output is in a new directory
`research/input-strategy-audit-20261027/runs/declared-irq-f5-fresh-20261030/`.

The machine-readable twin is
[`coverage-fresh-prefix-and-external-contract-20261030.json`](coverage-fresh-prefix-and-external-contract-20261030.json);
it records the SHA256 of each of the 202 input files it read, every fresh
measurement identity, the build commands with their exit codes and peak RSS, the
full external schema and all synthetic self-test cases.  The earlier reports
[`new-path-coverage-20261030`](new-path-coverage-20261030.md) and
[`coverage-comparison-contract-20261030`](coverage-comparison-contract-20261030.md)
(and their JSON twins) are **unchanged**; both still reproduce byte-identically
(§8).

## 1. What is now measured

The fresh prefix of each run is saved only in the raw per-component list form
(`<run>/fresh/fresh/local_commands.json`).  The converter
`scripts/normalize_fresh_local_commands.py` wraps those rows **verbatim** under
`sessions` into a `local_command_trace.v1` document — it validates every row and
refuses the whole input on the first defect, never repairs, drops or reorders a
record — and writes a provenance sidecar with the input SHA, the output SHA and
its own converter SHA.  The fresh commands are then replayed on an instrumented
copy of the **same pinned cache entry** that produced the original measurement.

| Run / scope | Component | DUT line/block (original) | DUT line/block (fresh) | Fresh commands | Fresh local ticks | Fresh `coverage.dat` SHA256 |
|---|---|---|---|---|---|---|
| `wb-timer/coverage-target` | `wb_timer_active` | **37 / 39** | **37 / 39** | 110 | 116 | `815c0f1c243fd863c6e3e345a81c59b8921a7970b289fb5d8fd3223f07a998e5` |
| `wb-timer/coverage-cpu` | `cpu` (Ibex) | **616 / 1782** | **616 / 1782** | 105 | 105 | `cde801ea5de9c17c83f215f820d6f8324143f26d15cd341d44376732cc5ecabc` |
| `apb-spi/coverage-target` | `spi_active` | **85 / 271** | **85 / 271** | 106 | 112 | `ccc6c0829c06e4601070873ec665c8b6b8c238019def7cb422e68e16bb2cfcac` |
| `ahb-sha/coverage-target` | `sha_active` | **359 / 614** | **359 / 614** | 134 | 146 | `09c15c7a39089d9e776921304a4ef8a2d11824e849b91efd1d1f87c198bba643` |

The fresh figures are **not** a second fuzz campaign: they are the same recorded
commands replayed on a freshly built instrumented copy of the same pinned build.
They reproduce the original count exactly, which is the identity check this
package exists to publish — not evidence of search quality or tool superiority.

Identity of the four fresh measurements (full values also in the JSON twin):

| Run / scope | Denominator SHA256 | Point set (normalised) SHA256 | Saved point map SHA256 (fresh) | Build digest |
|---|---|---|---|---|
| `wb-timer/coverage-target` | `2df82e5397fa2c42c37083bcad1635d220169179dfd4f7bdfa5d89015b944160` | `2df82e5397fa2c42c37083bcad1635d220169179dfd4f7bdfa5d89015b944160` | `51fd41eaaf766673a7cfb8d22b2abb40128193998b06152725e8b3922b82345f` | `f526592ac533fdfd499289646df2156ad58139099f7565b14b0ade7c5c1dcc6a` |
| `wb-timer/coverage-cpu` | `3611450ec1a63cccfd8f393d17875dc70f39a8bd7dc9314fc1d31777550c5280` | `3611450ec1a63cccfd8f393d17875dc70f39a8bd7dc9314fc1d31777550c5280` | `f6e6129328a43275204ce5c03ad5881cebbf342f57529e64079ef8329e7af0bb` | `a06ff3b42591ca1097f9b8c3a471080d4346199501245baeb66edd0fe718c8fc` |
| `apb-spi/coverage-target` | `c8dc60812118edd53b3113f51bd6cc33a3c59ed7ed12c74133d5e2eb861a96b7` | `c8dc60812118edd53b3113f51bd6cc33a3c59ed7ed12c74133d5e2eb861a96b7` | `0cbbaced97273e44f6bd5b016bbda87d2ad9e461e37e0b990d43aeeeef10ec0a` | `1e26eb155dfb6e8ca7d150a7d3bef59e032836b7a8fe2cf0490bd2ab77981d46` |
| `ahb-sha/coverage-target` | `6849c90f1bf5aaa1dd39587b574d3f0595ed168916292f86ea4075e07f2919db` | `6849c90f1bf5aaa1dd39587b574d3f0595ed168916292f86ea4075e07f2919db` | `2cd511fab7afb45d1d065d2fa3c35d56ee8572f1a7cf495adee051eeccae4ebe` | `7c80b436b4d4f0a9b1ad8c4b0ed8f226ff2263884f8c4b4fee8ec995a0ba44fa` |

The denominator is the canonicalised DUT point-identity set and is
build-directory independent, so it matches the original measurement exactly
(`2df82e53…`, `3611450e…`, `c8dc6081…`, `6849c90f…`, as published in the contract
package).  The **saved** point map differs from the original one by design: every
saved point embeds the absolute build directory it was measured in
(`…/declared-irq-f5-20261030/<run>/<scope>/inputs/…` vs
`…/declared-irq-f5-fresh-20261030/<run>/<scope>/inputs/…`), so
`e221d9ac…`→`51fd41ea…`, `568adb35…`→`f6e61293…`,
`009ab3fb…`→`0cbbaced…`, `87f0c9c4…`→`2cd511fa…`.  This package therefore
publishes, next to the saved hash, the **normalised** point identity sets:

- `dut.point_set_normalized_sha256` — the DUT point identity set, equal to the
  canonical denominator by construction and identical on both sides;
- `dut.point_universe_sha256` — the whole-harness point identity set
  (`0dab9b1f…`, `705afbb1…`, `9ecf4263…`, `2be99baa…`), identical on both sides,
  which proves the generated driver/runtime points are the same instrumented
  build inputs too.

Fresh-prefix command identity per run (converter evidence):

| Run | Raw fresh list SHA256 | Converted trace SHA256 | Components (records, local ticks) |
|---|---|---|---|
| `wb-timer` | `48983f4f5f48f6ecc26ee18574c1ae5e86026541bee3569953742ae5a874f210` | `0eefaa24e10614c2deb4c62f8309b7af2af529845e88a37ae8d2a54ccc4a4009` | cpu 105/105, wb_timer_active 110/116, wb_timer_idle 106/106 |
| `apb-spi` | `7a4c61555d15ec38b32544717df088303466b99c74cb850681cce45346ed4aaa` | `5382b603f012c9b0927c536f3e46a478552a03d196c635affeeb2f1ce0f536e5` | cpu 101/101, spi_active 106/112, spi_idle 102/102 |
| `ahb-sha` | `fe6896205f954e4a0fed70da7e05b9ebdf43e3d7f198dc28a576403c71fdc8f9` | `82436f69f0d8c6479ebaf9066e1780134e4e4bacb99ac4e72b135ff231f046f8` | cpu 125/125, sha_active 134/146, sha_idle 126/126 |

Converter: `scripts/normalize_fresh_local_commands.py`, own SHA256
`bed18fc9efe9ffaf8dad178470b04d881c00fc8dcb80222b7b382c82c7cbf768`, version 1.
The converted traces preserve each fresh invocation's own 32-hex execution nonce,
command counts, local ticks and replies; with the nonce normalised, the command
sequence **and** the reply stream equal the original prefix record for record, and
the workload SHA256 of each component equals the value published in the contract
package
(`3f6847b0…`, `0a7a4e94…`, `e6c0077b…`, `8d63048d…`), which is why the comparison
below is legal.

## 2. What comparison is now available: original vs fresh, instrumented

`compare_under_contract` (the existing function, not a second contract) is applied
to the original and fresh instrumented contracts of each scope.  All twelve
conditions are true on all four scopes, so each pair is
`status = comparable_contract`, `reasons = []`:

| Scope | Metric | Left (original) | Right (fresh) | hit_delta | Verdict |
|---|---|---|---|---|---|
| `wb-timer/coverage-target` | `verilator-line-block:wb_timer_active:dut` | 37 / 39 | 37 / 39 | **0** | `comparable_contract` |
| `wb-timer/coverage-cpu` | `verilator-line-block:cpu:dut` | 616 / 1782 | 616 / 1782 | **0** | `comparable_contract` |
| `apb-spi/coverage-target` | `verilator-line-block:spi_active:dut` | 85 / 271 | 85 / 271 | **0** | `comparable_contract` |
| `ahb-sha/coverage-target` | `verilator-line-block:sha_active:dut` | 359 / 614 | 359 / 614 | **0** | `comparable_contract` |

Conditions verified on both sides: same component and metric, identical
`source_files_sha256` (the declared structural-build DUT source files of the same
pinned cache entry), identical normalised point set and canonical denominator,
identical nonce-normalised `commands_sha256`, identical command count, local ticks
and `replies_sha256`, identical replay budget, explicit `offline` mode with
`online: false`, and `instrumented: true` on both sides.  The comparison document
records the two saved point-map hashes as provenance and states that they are
**not** required to be byte-equal because each embeds its own build directory:

```json
"point_set_identity": {
  "basis": "normalized-point-identities",
  "rule": "SHA256 of the sorted normalised point identities of the whole generated harness; the absolute build directory is not part of the identity",
  "left": "0dab9b1f…",
  "right": "0dab9b1f…",
  "saved_point_map_sha256": {"left": "e221d9ac…", "right": "51fd41ea…",
                             "note": "saved point maps embed their own build directory and are recorded, not required to be byte-equal"}
}
```

This is the first time in these packages that two **instrumented** covered/total
figures are compared, and the package records the old field explicitly:
`coverage_comparison_available = true` for all four scopes
(`fresh_comparisons.coverage_comparison_available = true`).  The earlier per-scope
`comparability.json` artifacts
(`status = comparable_prefix`, `coverage_comparison_available = false`,
`coverage_comparison_reason = fresh-prefix-not-instrumented`) were generated
before the fresh prefix existed; they are left in place unchanged and are
superseded for these four scopes by this package.  A zero hit delta between two
replays of the same commands is an identity check, not a superiority claim.

## 3. Budget representation (additive, opt-in)

`scripts/measure_new_path_coverage.py --extended-identity` now adds an explicit
`budget_record` (`offline_replay_budget.v1`) to the coverage document and the
same values to `contract.budget`, so "same budget" is a first-class field (the
`wall_seconds` values below are rounded for readability; the JSON twin has the
full floats):

```json
"budget_record": {
  "schema_version": "offline_replay_budget.v1",
  "mode": "offline",
  "commands": 110,
  "executed_commands": 110,
  "local_ticks": 116,
  "wall_seconds": {"instrumented": 0.0142, "plain": 0.0147},
  "tool_version": {"name": "verilator",
                   "version": "Verilator 5.051 devel rev vUNKNOWN-built20260806-e413e67",
                   "executable_sha256": "fb2cc573b1055cf096c90e1efc9966fe56bdb4b265c83590cf2a49f7a0defcdf",
                   "identity_source": "cache-manifest"},
  "build_digest": "f526592ac533fdfd499289646df2156ad58139099f7565b14b0ade7c5c1dcc6a",
  "binary_sha256": "9f10add5acd5493f515f68ca6a5651234213ed6738c1f414692b62a5e6eb4c93",
  "replay_bounds": {"max_commands": 2048, "max_input_bytes": 67108864,
                    "max_output_bytes": 67108864, "max_wall_seconds": 60},
  "search_budget": "unknown",
  "same_budget_rule": "identical replay_bounds and identical recorded command sequence; wall seconds are recorded but are not a budget"
}
```

`wall_seconds` is recorded, never treated as a budget; `tool_version` comes from
the verified cache manifest (so it is bound to `build_digest`), and
`search_budget` remains explicitly `unknown`.  All four scopes used the same
bounds (2048 commands, 64 MiB in/out, 60 s) and executed every recorded command
(110, 105, 106, 134).  The flag is **off by default**, so the recorded documents
keep their exact old shape and bytes (§8); the extended fields are additive keys
only.

## 4. The external same-budget comparison harness

We cannot run another fuzzing tool in this environment, so the deliverable is the
representation and verification side:
`scripts/check_external_coverage_contract.py` (own SHA256
`0a85a7be85ce7651ca68726ecb258b22a3089c955946abbd75c57e3350c23224`).  It
resolves one of our measured scopes through the same verified loader, accepts the
other tool's document in the strict schema below, validates every field and
prints/writes `comparable` or `not_comparable` with an exact per-field reason.  It
uses only stdlib file I/O and SHA256 — **no network access** — and it never
generates, fetches or implies a measurement.

```json
{
  "schema_version": "external_coverage_measurement.v1",
  "tool":       {"name": "...", "version": "...", "identity": "..."},
  "dut":        {"component": "...", "source_files_sha256": "<64 hex>",
                 "source_file_count": 1, "point_set_sha256": "<64 hex>",
                 "denominator_sha256": "<64 hex>", "total_points": 1},
  "workload":   {"identity": "recorded-command-sequence.v1", "commands": 1,
                 "commands_sha256": "<64 hex>", "local_ticks": 0,
                 "replies_sha256": "<64 hex>"},
  "budget":     {"replay": {"max_commands": 1, "max_input_bytes": 1,
                            "max_output_bytes": 1, "max_wall_seconds": 1},
                 "executed_commands": 0},
  "mode":       {"coverage": "offline|online|fixed_time", "online": false,
                 "fixed_time_coverage": false, "instrumented": true},
  "result":     {"covered": 0, "total": 1},
  "artifacts":  {"coverage_data_sha256": "<64 hex>"},
  "reproduction": "<the exact command that produced the measurement>"
}
```

Strictness: `additionalProperties: false` at every level, `required` lists as
above, digests `^[0-9a-f]{64}$`, positive integers for counts/totals, `number > 0`
for the wall bound, the mode enum, and at least one raw artifact hash including
`coverage_data_sha256`.  `point_set_sha256` means the **normalised** DUT point
identity digest; our extended contract publishes exactly that value as
`dut.point_set_normalized_sha256` (plus the raw saved hash as provenance).  The
full schema is in the JSON twin (`external_contract.schema`) and via
`--print-schema`.  The canonical rules a third party must reproduce are:

- **source set**: rows `{"path", "sha256"}` for the declared structural-build DUT
  source files, in declared order, path relative to the build `inputs/` root;
  digest = `sha256(json.dumps(rows, sort_keys=True, separators=(",", ":")))`.
- **point identity**: the saved Verilator field map with the source path made
  relative to the build `inputs/` root, serialised as
  `json.dumps(fields, sort_keys=True, separators=(",", ":"))`.
- **denominator**: `sha256(json.dumps(sorted(point_identities), separators=(",", ":"),
  ensure_ascii=True))` over the DUT points.
- **workload**: recorded command lines with the 32-hex execution nonce replaced
  by `{NONCE}`; digest = `sha256("\n".join(lines) + "\n")` over ASCII.
- **budget**: the replay bounds actually in force plus the executed command
  count; a search budget is never inferred.

Self-tests (`--self-test`) run 19 synthetic documents per scope, derived from the
real measured contract: **1 must be `comparable`** and **18 must be rejected for
the named reason**.  All four scopes pass: 76 checks, 4 comparable, 72 rejected,
including the named cases `dut-source-set-mismatch`, `point-set-mismatch`,
`denominator-mismatch`, `denominator-size-mismatch`, `workload-mismatch`,
`workload-length-mismatch`, `workload-tick-mismatch`, `replies-mismatch`,
`budget-missing`, `budget-mismatch`, `non-instrumented-measurement`,
`coverage-mode-mismatch` (online and fixed-time), `tool-identity-missing`,
`artifacts-missing`, `covered-exceeds-total`, `unknown-field:unexpected_extra` and
`unsupported-schema`.  A synthetic document is not a measurement: the package
publishes no external covered/total.

## 5. What is still unavailable, and the exact reason

- **An actual external tool measurement**:
  `external_contract.status = unavailable`,
  `reason = no-external-tool-measurement`.  No second tool has produced a
  document under this contract; the self-tests validate the validator, nothing
  more.  No aggregate or cross-tool number is published.
- **A search/time budget**: `reason = search-budget-not-recorded`.  The replay
  bounds (2048 commands / 64 MiB / 60 s) are a replay bound, not a fuzzing
  budget; `search_budget` stays `unknown` in every document.
- **The legacy per-scope comparability artifacts**:
  `reason = fresh-prefix-not-instrumented`, as generated.  They are superseded
  here but remain in place as historical artifacts; rewriting them is lead work
  because `research/` is read-only for this record.
- Nothing else is missing for these four scopes: every fresh measurement, original
  measurement, prefix and cache entry exists and verified.  A scope whose fresh
  measurement or cache entry were missing would be reported `unavailable` with
  its exact reason and no covered/total pair; the report builder never compares an
  instrumented side with a non-instrumented one.

## 6. Steps a third party must take to be compared

1. Pick a scope from this package or from
   [`coverage-comparison-contract-20261030.json`](coverage-comparison-contract-20261030.json);
   it names the component, the declared DUT source files
   (`dut.source_files_sha256`) and the canonical denominator
   (`dut.denominator_sha256`).
2. Build the same DUT from the same pinned source files and instrument
   line/block points with `verilator --coverage-line` (point kinds line/branch,
   all retained hierarchy instances; the saved `coverage.json` `build_argv`
   records the exact instrumentation command).
3. Replay the identical recorded command sequence, normalise the 32-hex execution
   nonce and publish `workload.commands_sha256`, `workload.commands` and
   `workload.local_ticks`.
4. Publish the replay bounds actually enforced and the executed command count;
   never report a covered count without its total.
5. Fill `external_coverage_measurement.v1` (schema above), include the raw
   artifact SHA256s and the reproduction command, and declare
   `mode.coverage = "offline"`, `mode.instrumented = true`, `online`/`fixed_time`
   false.
6. Run
   `PYTHONPATH=src:. python3 scripts/check_external_coverage_contract.py --scope <scope> --external <document.json> --output <dir>`
   and publish the resulting verdict together with its per-field reasons.

Any deviation is rejected with the exact field and reason; nothing is inferred
from prose, and a number without a matching denominator is never accepted.

## 7. Commands, exit codes and peak RSS

One instrumented build at a time, each wrapped in the shared lock; every command
is saved verbatim next to its output in
`research/input-strategy-audit-20261027/runs/declared-irq-f5-fresh-20261030/commands/`
(`*.command`, `*.exit`, `*.time`, `*.out`, `*.err`).

| Scope | Wall s | Peak RSS KiB | Exit | Compile jobs |
|---|---|---|---|---|
| `wb-timer/coverage-target` | 3.37 | 300196 | 0 | 4 |
| `wb-timer/coverage-cpu` | 6.79 | 318516 | 0 | 4 |
| `apb-spi/coverage-target` | 5.16 | 300232 | 0 | 4 |
| `ahb-sha/coverage-target` | 6.25 | 342096 | 0 | 4 |

Exact command (one line per scope; the full list is in the JSON twin):

```sh
PYTHONPATH=src:. python3 scripts/measure_local_coverage.py \
  --trace research/input-strategy-audit-20261027/runs/declared-irq-f5-fresh-20261030/wb-timer/normalized-local-command-trace.json \
  --component wb_timer_active \
  --cache runs/config-driven-20261028/cache/f526592ac533fdfd499289646df2156ad58139099f7565b14b0ade7c5c1dcc6a \
  --output research/input-strategy-audit-20261027/runs/declared-irq-f5-fresh-20261030/wb-timer/coverage-target \
  --max-commands 2048 --build-jobs 4
# wrapped as: flock /tmp/myfuzz-native.lock -c '<that command>'
# exit 0, wall 3.37 s, peak RSS 300196 KiB
```

`flock /tmp/myfuzz-native.lock` was used for all four builds; they ran
sequentially, so at most one Verilator build and four compile jobs existed at any
moment.

Offline reproduction of every figure in this package:

```sh
# convert the three fresh prefixes (deterministic; own SHA recorded)
for run in wb-timer apb-spi ahb-sha; do
  PYTHONPATH=src:. python3 scripts/normalize_fresh_local_commands.py \
    --input research/input-strategy-audit-20261027/runs/declared-irq-f5-20261030/$run/fresh \
    --output research/input-strategy-audit-20261027/runs/declared-irq-f5-fresh-20261030/$run/normalized-local-command-trace.json
done

# the four instrumented fresh replays (one at a time, flocked, -j 4)
# ... see the table above / JSON twin reproduction.measure

# re-verify each fresh measurement offline and derive its extended contract
PYTHONPATH=src:. python3 scripts/measure_new_path_coverage.py \
  --run research/input-strategy-audit-20261027/runs/declared-irq-f5-fresh-20261030/wb-timer/normalized-local-command-trace.json \
  --measurement research/input-strategy-audit-20261027/runs/declared-irq-f5-fresh-20261030/wb-timer/coverage-target \
  --cache runs/config-driven-20261028/cache/f526592ac533fdfd499289646df2156ad58139099f7565b14b0ade7c5c1dcc6a \
  --component wb_timer_active --contract --extended-identity \
  --output research/input-strategy-audit-20261027/runs/declared-irq-f5-fresh-20261030/wb-timer/verification-fresh

# the external contract self-tests and this package
PYTHONPATH=src:. python3 scripts/check_external_coverage_contract.py \
  --scope wb-timer/coverage-target --self-test
PYTHONPATH=src:. python3 scripts/report_fresh_prefix_and_external_contract.py \
  --runs-root research/input-strategy-audit-20261027/runs/declared-irq-f5-20261030 \
  --fresh-root research/input-strategy-audit-20261027/runs/declared-irq-f5-fresh-20261030 \
  --cpu-measurement research/input-strategy-audit-20261027/runs/declared-irq-f5-cpu-20261030/wb-timer/coverage-cpu \
  --output docs/reports/coverage-fresh-prefix-and-external-contract-20261030.json

PYTHONPATH=src:. python3 -m pytest tests/integration/test_fresh_prefix_coverage.py \
  tests/integration/test_external_coverage_contract.py \
  tests/integration/test_new_path_coverage_measurement.py \
  tests/integration/test_coverage_comparison_contract.py -q
```

The package is deterministic (no timestamps, sorted keys, repo-relative paths);
rerunning the report over the same saved files reproduces the same bytes, and the
committed test re-derives it and compares byte-for-byte.

## 8. What a rerun of the old commands would notice

- `docs/reports/new-path-coverage-20261030.json` still reproduces
  byte-identically (`cmp` identical) from
  `scripts/report_declared_f5_coverage.py`, and
  `docs/reports/coverage-comparison-contract-20261030.json` still reproduces
  byte-identically from `scripts/report_coverage_comparison_contract.py`.
  Neither old report nor any recorded artifact under `research/`/`runs/` was
  modified.
- `scripts/measure_new_path_coverage.py`: new opt-in `--extended-identity`
  (coverage `budget_record`, `point_set_normalized_sha256`,
  `point_universe_sha256`; contract `dut.point_universe_sha256`,
  `dut.point_set_normalized_sha256` and `budget.{commands,local_ticks,wall_seconds,tool_version,build_digest}`),
  and `compare_under_contract` now compares the normalised point set when **both**
  contracts carry it, falling back to the saved point-map hash otherwise.  The
  default document shape and the default comparison results are unchanged.
- New `scripts/normalize_fresh_local_commands.py` (reviewed converter: all-or-
  nothing validation, deterministic output, provenance sidecar with the input,
  output and converter SHAs), new
  `scripts/check_external_coverage_contract.py` (strict schema, per-field
  reasons, `--self-test`, `--print-schema`, no network),
  new `scripts/report_fresh_prefix_and_external_contract.py`, new tests
  `tests/integration/test_fresh_prefix_coverage.py` and
  `tests/integration/test_external_coverage_contract.py`, this report, its JSON
  twin, and the new measurement directory
  `research/input-strategy-audit-20261027/runs/declared-irq-f5-fresh-20261030/`.
- The new reports/scripts add no behavior change to any existing default
  invocation; the four fresh builds are the only heavy commands, and they are
  recorded above with exits and RSS.
