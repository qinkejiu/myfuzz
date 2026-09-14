# SoC composition and RFuzz acceptance report (2026-09-15)

**结论：P13 之后本项目**未**达到全局完成。** P12 的运行时矩阵、P13 的八格插桩覆盖、
P14 的官方 RFuzz 闭环（两款 CPU）与 P16 的全量回归都已取得可复现证据；但 P15
（每任务 300 秒、合计≥160 分钟有效 fuzz）按用户要求**明确不做**，因此"八配置 × 三模式 ×
300 秒 + 8 个 bias-off 对照"这一条验收门槛没有满足。

This report supersedes `soc-acceptance-20260914.md` for the state after the
CVA6 fabric work. It records only what was measured on this branch; every claim
below names the command that produced it.

## 1. What changed since the previous report

The previous report listed six missing items. Four are now closed, two are not.

| Previous gap | State now | Evidence |
|---|---|---|
| Ibex and CVA6 each need a real client-driven SoC fuzz run with source-backed CPU/peripheral internals observed through IPC | closed | §5 (P13 eight-cell run), §6 (CVA6 campaign) |
| CVA6 has elaboration evidence but no runtime evidence for the generic 64-bit fabric, high/low MMIO lanes or the PULP IRQ path | closed | §4 (`cva6-pulp/mixed`, `cva6-opentitan/*`, `cva6-mixed/*`, `cva6-zipcpu/*` all OK) |
| The eight cells have not completed the three-mode runtime matrix | closed | §4 (24/24) |
| A full eight-cell instrumented coverage run is outstanding | closed | §5 |
| 300-second-per-task campaigns | **not done (P15, out of scope)** | — |
| Retained corpus rebuilt and replayed for all eight cells | **partial**: both CPUs have a rebuild+replay proof, not all eight cells | §6 |

Two root causes recorded in the handover were wrong and were corrected by
measurement; both are documented in `soc-execution-progress-20260914.md`:

* the TL-UL failure was not a data-path problem but a missing structural
  address-narrowing stage, now inserted in front of the target with the window as
  the losslessness proof, and `beat_to_tlul.sv:124` is unchanged;
* the CVA6 fetch failure was not a burst or entry-offset problem.  The
  beat-instrument wrapper drove its response-hold valid without connecting the
  held payload, so the AXI adapter latched zero for every read and the core
  never saw the entry `jal`.

## 2. Pinned sources

`configs/soc/sources.lock.json`; re-derive with
`PYTHONPATH=src python3 scripts/verify_soc_sources.py --elaborate`.

| component | top module | root | revision |
|---|---|---|---|
| ibex | ibex_top | third_party/rfuzz/upstream/ibex | git:34b0705760ef3d |
| cva6 | cva6 | third_party/cva6_upstream_reference | git:2e1336dcff3d1a |
| opentitan_uart | uart | third_party/soc-opentitan | git:fca045df919a26 |
| opentitan_gpio | gpio | third_party/soc-opentitan | git:fca045df919a26 |
| pulp_gpio | apb_gpio | third_party/soc-pulp-apb-gpio | git:f82caeb7f7d894 |
| pulp_spi | apb_spi_master | third_party/soc-pulp-apb-spi | git:3fce81084b1587 |
| pulp_spi_dependencies | spi_master_controller | third_party/soc-pulp-axi-spi | git:ee219078353a76 |
| zipcpu_uart | wbuart | third_party/soc-zipcpu-wbuart | git:f43a6b83c3a70f |
| zipcpu_timer | ziptimer | third_party/soc-zipcpu | git:42606d2d6ef55d |

Two real CPUs and six real peripherals across three upstream projects.  Per
family both pinned peripherals are instantiated, and each mixed cell
instantiates one from each family.

## 3. Commands that reproduce this report

```bash
# full regression: composition + protocols + integration + top level
PYTHONPATH=src python3 -m unittest discover -s tests -p 'test_*.py'
#   Ran 1604 tests in 215.335s -- OK (skipped=28)

# P10/P11/P12 render + Verilator elaboration of all eight cells
MYFUZZ_SOC_REAL=1 PYTHONPATH=src python3 -m unittest tests.integration.test_soc_renderer_cells
#   Ran 10 tests -- OK

# P12 runtime half: eight cells x three modes, real CPU and real peripherals
MYFUZZ_SOC_REAL=1 PYTHONPATH=src python3 -m unittest \
  tests.integration.test_soc_matrix_runtime.SocMatrixRuntimeTests
#   Ran 8 tests in 72.214s -- OK ; MYFUZZ_SOC_MATRIX_TIMING runs=24 within_budget=True

# P13 instrumented eight-cell coverage run
MYFUZZ_SOC_REAL=1 MYFUZZ_RFuzz_CLIENT=runs/rfuzz_client_native_build/target/debug/kfuzz \
  PYTHONPATH=src python3 -m unittest tests.integration.test_soc_coverage_run
#   Ran 4 tests in 1155.263s -- OK

# P14 official RFuzz closed loop, real client, retained evidence + rebuild replay
MYFUZZ_SOC_REAL=1 MYFUZZ_RFuzz_CLIENT=runs/rfuzz_client_native_build/target/debug/kfuzz \
  PYTHONPATH=src python3 -m unittest tests.integration.test_soc_rfuzz_build
#   Ran 15 tests in 118.410s -- OK

# real CPU acceptances (no skips when the flag is set)
MYFUZZ_SOC_REAL=1 PYTHONPATH=src python3 -m unittest \
  tests.integration.test_soc_real_ibex tests.integration.test_soc_real_cva6
#   Ran 18 tests in 33.512s -- OK

# preflight: 24 main + 8 bias-off control tasks, nothing unsupported
PYTHONPATH=src nice -n15 python3 scripts/run_soc_campaigns.py \
  --matrix configs/soc/matrix.json --output runs/soc-acceptance/p16-preflight-20260915 \
  --seconds 300 --seed 20260914 --preflight-only
#   {"tasks_planned":32,"main_tasks":24,"bias_off_tasks":8,"unsupported":[],
#    "effective_budget_seconds":0,"status":"preflight-only"}
```

The preflight plans 32 tasks and reports `effective_budget_seconds: 0` because
it runs nothing; it is not a substitute for P15.

### A note on verifying the commits from scratch

`third_party/` holds the pinned upstream checkouts and is **not** committed, so a
clean `git archive HEAD` checkout cannot run the tests that read those sources.
Verifying the committed tree therefore used a detached worktree at HEAD with the
pinned checkouts symlinked in, and the result is worth stating precisely:

* `tests/protocols` passes at HEAD (123 tests OK); it reads files and tolerates
  the symlinked checkouts.
* `tests/composition` passes in the working tree (522 OK) and no composition test
  reads any file the parallel workstream has modified, so that result transfers
  to HEAD unchanged.
* Anything that re-derives a source root refuses a symlink outright
  (`cva6-source-root:symlink`), which is a deliberate fail-closed property of the
  code: the CVA6 closure revalidation fails from the symlinked worktree for that
  reason alone. Full from-scratch verification of those paths would need the
  pinned checkouts materialised inside the checkout rather than linked.

So the strongest statement this round can make is: the working tree equals HEAD
except for the six files listed in §9, the full regression passes on that tree
(1604 OK), and the committed test modules that the workstream's edits shadow were
re-run at HEAD under `tests/protocols`.

## 4. Eight cells x three modes (P12 runtime half)

`runs/soc-matrix-runtime/<cell>/<mode>/observations.json`, 24 runs, all
`status=OK`, `window_error=0` everywhere.

| cell | mode | cycles | cpu_tx | cpu window | fuzz window | cpu_flag |
|---|---|---|---|---|---|---|
| cva6-opentitan | cpu_only | 1255 | 27 | 3 | 0 | 0xf00d0001 |
| cva6-opentitan | mmio_only | 662 | 0 | 0 | 3 | — |
| cva6-opentitan | mixed | 1309 | 27 | 3 | 3 | 0xf00d0001 |
| cva6-mixed | cpu_only | 630 | 24 | 2 | 0 | 0xf00d0001 |
| cva6-mixed | mmio_only | 53 | 0 | 0 | 2 | — |
| cva6-mixed | mixed | 667 | 24 | 2 | 2 | 0xf00d0001 |
| cva6-pulp | cpu_only | 585 | 22 | 2 | 0 | 0xf00d0001 |
| cva6-pulp | mmio_only | 49 | 0 | 0 | 2 | — |
| cva6-pulp | mixed | 618 | 22 | 2 | 2 | 0xf00d0001 |
| cva6-zipcpu | cpu_only | 605 | 23 | 3 | 0 | 0xf00d0001 |
| cva6-zipcpu | mmio_only | 67 | 0 | 0 | 3 | — |
| cva6-zipcpu | mixed | 656 | 23 | 3 | 3 | 0xf00d0001 |
| ibex-opentitan | cpu_only | 840 | 104 | 3 | 0 | 0xf00d0001 |
| ibex-opentitan | mmio_only | 650 | 0 | 0 | 3 | — |
| ibex-opentitan | mixed | 890 | 107 | 3 | 3 | 0xf00d0001 |
| ibex-mixed | cpu_only | 840 | 104 | 3 | 0 | 0xf00d0001 |
| ibex-mixed | mmio_only | 650 | 0 | 0 | 3 | — |
| ibex-mixed | mixed | 890 | 107 | 3 | 3 | 0xf00d0001 |
| ibex-pulp | cpu_only | 223 | 27 | 2 | 0 | 0xf00d0001 |
| ibex-pulp | mmio_only | 45 | 0 | 0 | 2 | — |
| ibex-pulp | mixed | 256 | 29 | 2 | 2 | 0xf00d0001 |
| ibex-zipcpu | cpu_only | 227 | 27 | 3 | 0 | 0xf00d0001 |
| ibex-zipcpu | mmio_only | 61 | 0 | 0 | 3 | — |
| ibex-zipcpu | mixed | 280 | 30 | 3 | 3 | 0xf00d0001 |

How to read this so that it is not mistaken for "the RTL ran":

* `cpu_flag=0xf00d0001` is written by the **generated boot program** after it
  compared the value it read back from the real peripheral against the value it
  wrote. `0xf00d0002` means mismatch. So a pass requires a real CPU load, a real
  peripheral register read, and agreement.
* `mmio_only` has `cpu_tx=0` **by contract**: the CPU is held in reset for the
  whole test and the synthetic `fuzz_mmio_master` must complete the same
  operations. Its warrant is `window_done_fuzz` 2–3 with `window_error=0` and a
  real side effect, not a CPU flag.
* `window_error=0` on all 24 runs means no window transaction was answered with
  an error, so nothing here passes by continuous DECERR.

## 5. P13: instrumented eight-cell coverage run

`tests.integration.test_soc_coverage_run`, 4 tests OK in 1155 s. Per cell it
builds through the production campaign builder, runs a short real campaign, and
then checks the coverage the fuzzer received rather than the coverage the harness
intended to send.

* the artifact and the live report both record
  `coverage_kind = source-instrumented-rtl-branch-u8-saturating`
  (was `sampled-output-bit-events-u8-saturating`);
* the universe separates `cpu` / `ip` / `fabric` / `model` / `harness`, and both
  `cpu` and `ip` points are among the 128 observed counters in every cell;
* the retained corpus trace - what the client actually kept over the IPC channel
  - carries nonzero counters that resolve to instance paths under
  `myfuzz_soc_top` and include at least one real CPU or IP point;
* the retained universe document re-hashes to the `universe_hash` recorded in
  the artifact.

Measured detail on `cva6-pulp/mixed` (8791-bit instrumented vector, 8447-point
universe): cpu 8235 / ip 319 / fabric 176 / model 22 / harness 39; the 128
observed counters are spent 64 cpu + 64 ip; the retained corpus carries 26
nonzero counters that resolve to, for example,
`myfuzz_soc_top/u_pulp_spi/u_apb_spi_master/u_spictrl/u_rxreg` (ip) and
CPU-internal Ibex/CVA6 points (cpu).

**Limits, stated rather than hidden:** the run is 8 s per cell because its
purpose is to prove branch feedback reaches RFuzz, not to measure coverage; the
harness exposes 128 counters against thousands of points and every artifact
records `unobserved_branch_points`; `coverage_observation_plan` interleaves CPU
and IP points so a large CPU subtree cannot starve the peripherals out of that
budget.

## 6. P14: official RFuzz closed loop, both CPUs

`tests.integration.test_soc_rfuzz_build`: 15 tests OK / 118 s, which covers
`ibex-pulp` end to end (receipts, corpus, input-transport identity, rebuild and
replay of the retained corpus).

For the second CPU, one CVA6 campaign with the production builder and the real
client (15 s, `runs/p16-cva6-replay/`):

```text
status=completed_with_client_termination  final_status=passed_with_client_termination
coverage_kind=source-instrumented-rtl-branch-u8-saturating
tests=20643   fifo_reply_receipts=13656   coverage_records=13656
counter_maxima: 21 of 128 nonzero (max 5);  hits resolve to ip 18 / cpu 3
replay.status=passed  entries=1  binary_sha256=sha256:ae0ef5d0...  counters reproduced
```

So both CPUs have a real client-driven fuzz run whose retained corpus was
replayed by an independently rebuilt binary with the coverage identity
reproduced. The eight-cell campaign with per-task rebuild and replay remains
P15 work.

## 7. P16 review checklist

| Item | Where it is enforced | Verified by |
|---|---|---|
| old entry-point compatibility | `composition/auto.py` and `protocol_composer.py` re-export every extracted name | `tests/composition/test_legacy_entrypoint_compatibility.py` (byte-identical fixture matrix + golden digest) |
| name independence | adapters are selected from protocol and capability facts, never a CPU name | `tests/protocols/test_soc_target_adapters_rtl.py`, `tests/composition/test_processor_adapters.py` |
| unique driver | `soc_plan._build_nets` counts drivers per net and errors unless exactly one, recording `driver_count: 1` and `evidence.observed_drivers` | `tests/composition/test_soc_contracts.py` (asserts both, plus duplicate-driver rejection) |
| memory / IRQ truth source | one physical memory shared by aliases; MMIO reads always come from the real IP; IRQ only from declared routes | `tests/integration/test_memory_mmio_coexistence.py`, `tests/composition/test_soc_fabric_plan.py`, IRQ routing tests |
| CPU burst / width limits | `axi4_processor_memory_adapter` accepts only ARLEN<=1 INCR and rejects the rest with DECERR; `mmio_width_adapter` refuses spanning accesses unless the window declares them safe | `tests/protocols/test_axi4_processor_memory_adapter_rtl.py`, `tests/protocols/test_soc_fabric_rtl.py` |
| late responses | router and width adapter drain and discard a response that arrives after reset (`stale_pending`) | `tests/protocols/test_soc_fabric_rtl.py` (late-response and full-test-reset cases) |
| coverage type | sampled input/output events are rejected as branch evidence; only instrumented RTL bits enter the universe | `tests/integration/test_soc_coverage.py`, `tests/integration/test_soc_coverage_run.py` |
| replay identity | corpus replayed by a rebuilt binary must reproduce the coverage identity | `tests/integration/test_soc_rfuzz_build.py` |

## 8. Second recoverable cleanup (P0 list)

Already executed on 2026-09-14 20:42 by the previous round: batch `P16-batch2`
quarantined 198 entries, post-audit recorded eligible 0, and
`docs/REPOSITORY_ORGANIZATION.md` holds the disposition table and the restore
command. A fresh read-only audit on 2026-09-15 finds 3488 entries with 223
eligible, and all 223 are regenerated `__pycache__/*.pyc` compiled caches with a
clean, untracked, unreferenced source. No source or artifact migration is
warranted, so this round records zero migrations rather than re-quarantining
caches that Python recreates on the next import.

Reproduce the audit and recover any batch:

```bash
PYTHONPATH=src python3 scripts/audit_repository.py \
  --output runs/repository-audit/p16-second-pass/inventory.json \
  --quarantine-list runs/repository-audit/p16-second-pass/quarantine-list.json
PYTHONPATH=src python3 scripts/audit_repository.py \
  --restore runs/quarantine/<batch>/manifest.json
```

## 9. Errors and limitations

* **P15 not run.** No 300-second-per-task campaign, no 160-minute aggregate, no
  all-eight-cell bias-off comparison. Nothing in this report may be read as
  coverage or statistical significance from long fuzzing.
* **Coverage is bounded and partial.** 128 counters per cell over thousands of
  branch points; `unobserved_branch_points` is recorded per build. Interaction
  events are named separately and excluded from branch feedback by default.
* **Compact Verilog-2001 needed an explicit setting.** `wbuart`, `txuart`,
  `rxuart` and `ziptimer` write `always @(posedge clk) if (...) begin ... end`
  with a single-statement body. Those blocks produced zero points until
  `runtime.single_statement` measured them; with the setting off the skip is now
  counted as `runtime_single_statement_body_not_enabled` instead of being
  silent.
* **Instrumented builds need their own memory budget.** A branch-instrumented
  cell is much larger than the bare render; the campaign's 512 MiB default
  terminated the CVA6+OpenTitan compile, so the build phase uses
  `BUILD_MEMORY_LIMITS` (soft 3 GiB / hard 4 GiB). The simulator keeps the
  conservative default.
* **The official client cannot always exit cleanly.** The pinned client panics
  in `queue.rs` during shutdown drain; a run bounded by our drain is recorded as
  `completed_with_client_termination` with its receipts, corpus and termination
  cause, and is never recorded as `completed`.
* **`GOLDEN_MATRIX_DIGEST` was already stale at `3a1f87a`** (a clean archive
  computes `e63647ef...`, not the recorded `9cbed41b...`). It was re-baselined to
  `2f4353a8...` with that history recorded in the comment.
* **Uncommitted work by a parallel workstream is untouched**:
  `.superpowers/sdd/task-2-report.md`, `configs/soc/cva6-pulp.json`,
  `docs/reports/soc-acceptance-20260914.md`,
  `docs/系统总览与RFuzz约束组合示例_20260909.md`,
  `tests/integration/test_soc_real_cva6.py`,
  `tests/protocols/test_axi4_processor_memory_adapter_rtl.py`, and the untracked
  `tests/fixtures/soc_cva6_pulp_boot.hex`,
  `tests/fixtures/soc_ibex_pulp_loop.hex`,
  `tests/integration/rtl/soc_cva6_pulp_tb.sv`.

## 10. Acceptance decision

Not complete. P12's runtime half, P13 and P14 are closed with the evidence above,
and P16's regression and review are done, but the plan's acceptance condition
requires every cell to clear a 300-second campaign in all three modes plus a
bias-off control, and that is P15, which was excluded from this round by explicit
instruction. The project must therefore not be marked complete; the remaining
work is exactly P15 (with the client-shutdown caveat in §9) plus per-cell
campaign replay.
