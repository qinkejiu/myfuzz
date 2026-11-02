# Directed and native-ready IRQ validation (reset, exception, multi-source, cross-protocol) — 2026-10-30

Scope of this record: **software gates and a native script that has not been run
here**. No RTL campaign, no DUT simulation and no Verilator build was started for
this document. The only native artifacts cited are the *previously saved*
declared-IRQ journals under
`research/input-strategy-audit-20261027/runs/declared-irq-20261029/`, read
read-only to validate the new script's evidence derivation. Nothing below is a
native pass.

## What was added

| File | Purpose |
|---|---|
| `tests/integration/test_directed_irq_matrix.py` | reset, exception and multi-source gates over the pinned CPU contracts, the real compiled scenario config and the saved declared-IRQ journals |
| `tests/integration/test_directed_irq_matrix_config.py` | validates `configs/scenarios/directed-irq-matrix.json`, the native script's preflight/refusals, the cross-protocol admission matrix and the native derivation replayed over saved journals |
| `tests/integration/test_new_path_coverage_measurement.py` | `unavailable`-vs-measured contract of the coverage script, including a real saved measurement and a real paired comparability document |
| `scripts/check_irq_protocol_matrix.py` | CPU protocol adapter × declared target protocol admission gate; builds artifacts/sessions only |
| `scripts/run_directed_irq_native.py` | native CLI for the lead (`--config/--case/--output/--native`), plus `--preflight` |
| `scripts/measure_new_path_coverage.py` | saved-prefix line/block DUT coverage + comparability document, `unavailable` when inputs are missing |
| `configs/scenarios/directed-irq-matrix.json` | the case list and its declared evidence layers, native readiness and refusals |
| `docs/reports/directed-irq-native-validation-20261030.md` | this record |

## Commands and results (all run with `PYTHONPATH=src`; this repository has no `conftest.py`)

```
PYTHONPATH=src python3 -m pytest \
  tests/integration/test_directed_irq_matrix.py \
  tests/integration/test_directed_irq_matrix_config.py \
  tests/integration/test_new_path_coverage_measurement.py -q
# 41 passed, 1 skipped

PYTHONPATH=src python3 -m pytest \
  tests/scenario/test_irq_serial_certificates.py tests/scenario/test_irq_delivery_group.py \
  tests/scenario/test_irq_delivery.py tests/scenario/test_gpio_irq_dependency_evidence.py \
  tests/scenario/test_irq_boundary_evidence.py tests/scenario/test_irq_dependency_evidence.py \
  tests/scenario/test_irq_dependency_runner.py tests/scenario/test_timer_irq_group.py \
  tests/scenario/test_declared_irq_transport.py tests/scenario/test_declared_irq_group_review.py \
  tests/scenario/test_registered_irq_serial.py tests/scenario/test_irq_return_successor.py \
  tests/scenario/test_gpio_reset_review.py tests/scenario/test_gpio_consumption_versions.py -q
# 183 passed

PYTHONPATH=src python3 -m pytest \
  tests/integration/test_cv32e20_shared_config.py tests/integration/test_cv32e20_irq_smoke_script.py \
  tests/integration/test_compare_local_harness_coverage.py tests/integration/test_measure_local_coverage.py -q
# 30 passed
```

Running the new files together with the four related integration files is
`71 passed, 1 skipped`. The single skip is the ~41 s compiled-preparation test,
which is opt-in:

```
PYTHONPATH=src MYFUZZ_DIRECTED_IRQ_SLOW=1 python3 -m pytest \
  tests/integration/test_directed_irq_matrix.py::test_shared_scenario_builds_that_group_from_real_artifacts -q
# 1 passed
```

Per-file breakdown of the 41: `test_directed_irq_matrix.py` 19 passed / 1 skipped,
`test_directed_irq_matrix_config.py` 14 passed,
`test_new_path_coverage_measurement.py` 8 passed.

## What the software gates prove

### Reset (`test_directed_irq_matrix.py`, "reset" section)

Real documents: the single `cpu_external_irq_taken` and the single `intr=1`
`cpu_retire` of the saved `spi-ibex-v1` journal.

- The two real documents certify exactly one `irq_serial_certificate.v1`
  (`decision_serial == retirement_serial == 1`).
- Inserting a measured barrier of each kind the reducers honour
  (`reset_barrier`, `cpu_reset`, `gpio_reset_resource`) between them drops the
  pending lineage for good: 0 certificates, `pending_count == 0`, rejection
  reason `unmatched_retirement_serial`, and the same retirement offered again
  still refuses.
- A post-barrier pair certifies only with a fresh epoch *and* a fresh take
  identity (`take_key = ['cpu', 1, 1]`); reusing the pre-reset identity is
  refused with `take_key_scope_mismatch`.
- `GpioConsumptionTracker` (the GPIO dependency reducer) proves the installed
  register/ISR state is invalidated: the pre-reset commit resource is never a
  dependency of a fresh-epoch commit, the old-epoch access is refused with
  `rejected` + `epoch_without_advanced_reset`, the same access at the fresh
  epoch is `observed`, and a reset that does not advance the epoch is refused
  with `reset_epoch_did_not_advance`.
- `GpioNativeIrqEvidenceConsumer` drops its pre-reset pending native state on a
  `reset_barrier` (`_native`, `_events`, `_accepted`, `_serial_pending` empty),
  so the post-reset copy of the take cannot bind to the dropped sample; its
  report keeps `native_authority=false`, `reward_eligible=false`,
  `grants_prerequisites=false`, `isr_mmio='unknown'`, `irq_consumption='unknown'`.
- `ScenarioRunner._effective_inputs` (production guard) refuses a member sample
  of the pre-reset epoch after the session epoch advances
  (`IRQ group source epoch changed; native resample required`) and accepts the
  same frame once fresh-epoch samples arrive.

### Exception (`test_directed_irq_matrix.py`, "exception" section)

Uses the real pinned contracts only: `ibex_irq_receipt_contract()`,
`cv32e20_irq_receipt_contract()` and — because it landed concurrently during
this session — `cv32e40p_irq_receipt_contract()`. Each is imported inside the
test and the test **skips** when the module is not importable.

- The only lineage-minting decision probe (`irq_taken_pre`) is a conjunction of
  `pc_set`, `csr_save_cause`, an IRQ vector equality
  (`exc_pc_mux_o == …EXC_PC_IRQ`) and exactly one `exc_cause_o ==` atom whose
  value is a single literal: `ibex_pkg::ExcCauseIrqExternalM`,
  `cve2_pkg::EXC_CAUSE_IRQ_EXTERNAL_M`, and `5'd11` (= `input_bit_offset` =
  `decision_acceptance.source_id`) for CV32E40P. One equality against one
  literal is why a synchronous-exception cause value cannot select it.
- CV32E40P proves the exclusion explicitly: `irq_redirect_pre` is
  `pc_set & exc_pc_mux != EXC_PC_IRQ & != EXC_PC_DBD & != EXC_PC_DBE` — a
  non-IRQ exception redirect (and debug entry) is mutually exclusive with the
  acceptance atom's `== EXC_PC_IRQ`, never asserts `csr_save_cause`, and all of
  `irq_redirect_pre`, `irq_taken_pre`, `irq_ack_pre`, `irq_id_pre`,
  `irq_entry_pc` exist with declared widths (id width 5). Its retirement
  authority is `pc_insn_order_only` and `intr` is in
  `unobserved_retirement_fields`.
- Debug/NMI diversion refuses through production code:
  `native_irq_retirement_diversion_fields` / `native_irq_retirement_diverted`
  return `True` for any single non-zero diversion field and for a missing
  observation; the CVE2 masked probe contains `debug_mode_q | nmi_mode_q` and
  its pinned sideband zeroes `irq_pending_q/irq_intr_q/irq_stage_q` under
  debug/NMI. CV32E40P masks on `debug_mode_q` and its redirect probe excludes
  `EXC_PC_DBD/DBE`; it declares diversion `unobservable` rather than inventing
  a field.
- Notification is not source authority in every contract
  (`actual_post_extension_even_without_retirement`,
  `…fields_not_source_authority`, `rvfi_intr_is_not_driven_so_no_post_edge…`).
- Real-document refusals: the saved take is admitted only with
  `irq_taken_pre == 1` (production `GpioNativeIrqEvidenceConsumer._take`); the
  same document with `irq_taken_pre = 0` (a redirect/debug decision) is not
  admitted. Of the 44 real retirements exactly one has `intr == 1` and only that
  one carries a nonzero retirement serial; the whole journal yields exactly one
  certificate. The same retirement re-stamped as a synchronous trap
  (`intr=0, trap=1`) is refused with `retirement_not_interrupt`.

### Multi-source (`test_directed_irq_matrix.py`, "multi-source" section)

The real `IrqDeliveryGroup` document is reconstructed from the saved
`spi-cv32e20-v1` frame plus its `config.json` and must reproduce the recorded
`group_sha256` byte-for-byte (it does). Every join is re-derived by the
production `saved_irq_group.frame_for_sample` over a contiguous, renumbered
journal window; no original event id is trusted.

- Unique attribution: `attribution_status='unique'`, `unique_source =
  'spi_active.events_o'`, one `irq_group_acceptance`, `grants_prerequisites=false`.
- Two simultaneously active members (the idle member is given a real-shaped
  rising sample and pulse window): `attribution_status='joint'`,
  `unique_source=None`, value 1, and `ScenarioRunner._guard_irq_group_input_context`
  clears the planned single-source context, while the same plan survives a
  unique frame. That is the "no credit" rule at the level that awards context.
- Unknown origin: a member without `native_source` is refused
  (`member sample reference missing`), a reference to another component's
  sample is refused (`member native sample/epoch mismatch`), and
  `IrqDeliveryGroupState.observe` refuses an incomplete reference
  (`IRQ group native member reference required`).
- A take without its delivery frame cannot be joined (`frame missing/duplicate`)
  while the serial certificate still certifies its one serial equality — and
  that certificate carries no group/source attribution field, so a serial
  certificate is explicitly not a delivery attribution.
- Overrun: `IrqPulseDelivery` goes to `unsupported_irq_overrun`, records
  `policy='terminate_unsupported'`, opens no second `pulse_start`, and the
  honest frame at the un-delivered tick is value 0 with `unique_source=None`; a
  frame claiming that delivery is refused with `pulse/OR value mismatch`.
- Reset-cancelled pulse: `pulse_cancelled_by_reset` is recorded, `input_at`
  returns 0 afterwards, `IrqDeliveryGroupState.reset()` clears `last_delivery`,
  and a frame cannot be built again until fresh native samples exist.
- The compiled config `configs/scenarios/compiled-f1-f6-cv32e20-gpio-dma-shared`
  declares the real two-member group (`shared-external`: `dma.irq` pulse 16 +
  `peripheral.interrupt` pulse 4 → `cpu.irq_external_i`); the declaration test
  validates the group document from the supplement, and the opt-in test above
  builds it from the real artifacts through `shared_f6_assembly.shared_irq_group`.

### Cross-protocol admission matrix (`scripts/check_irq_protocol_matrix.py`)

5 CPU protocol adapters × 3 declared target protocols = 15 combinations. The
gate builds the CPU artifact and the target artifact through the public
factories, constructs the real sessions **without preparation**, installs the
explicit one-member `IrqDeliveryGroup` and asks `verify_group_sessions` to admit
or refuse it. No `prepare_local`, no process, no DUT.

```
PYTHONPATH=src python3 scripts/check_irq_protocol_matrix.py \
  --config configs/scenarios/directed-irq-matrix.json --output <dir>/protocol-matrix.json
# status=complete counts={admitted: 9, refused: 6, error: 0} dishonest=[]
```

- Admitted (9 at the time of this run): `obi-cv32e20`, `obi-ibex`,
  `obi-cv32e40p` × {`apb-spi`, `wishbone-ziptimer`, `ahb-sha`}, each with the
  `declared-output.v1` mapping (`physical_port`/`runtime_name`/width), the
  target's real `physical_exports` row, the group document and its sha256, and
  the CPU source-verification document (`source_status='source_verified'`).
  The `obi-cv32e40p` row is conditional on its contract module being importable
  (it landed during this session); without it the expected shape is 6 admitted /
  9 refused, and both shapes are accepted by the config test.
- Refused by name (6 always): `wishbone-picorv32` and `ahb-lite-cvw` × the three
  targets, with `refusal_code='unregistered-native-IRQ-CPU-adapter'`,
  `stage='cpu-source-contract'` and the CPU profile id (`picorv32_wb`, `cvw`) in
  the refusal. Both have real session factories
  (`GeneratedWishboneCpuSession`, `GeneratedAhbMemorySession`) but no registered
  native IRQ source contract, so the combination is refused instead of skipped.
- The gate's expectation table lives in the matrix JSON and every row carries
  `honest: true`; a mismatch would make the script exit 2.

### Coverage / comparability (`scripts/measure_new_path_coverage.py`)

The script reuses `compare_local_harness_coverage.load_run` (file hashes, original
cache identity, instrumentation, replay protocol/ticks, all Verilator points
including zeros) and `measure_local_coverage.select_recorded_session` (the saved
component prefix must equal the measured `commands.txt`/`replies.txt`). It builds
nothing and replays nothing.

Real saved input (read-only):

```
PYTHONPATH=src python3 scripts/measure_new_path_coverage.py \
  --run research/input-strategy-audit-20261027/runs/adapter-matrix-20261029/spi-cv32e20-v1/seed-7-state-none/original \
  --measurement research/input-strategy-audit-20261027/runs/adapter-matrix-20261029/spi-cv32e20-v1/seed-7-state-none/coverage-measurement/measurement \
  --cache runs/config-driven-20261028/cache/473092ef39384de71033e7e877609f71cde3fe492627306a5c6ab4ca1dd71bdd \
  --output <dir> --focus spi_master_controller
# status=available metric=verilator-line-block:peripheral:dut covered=72 total=271
# focus spi_master_controller: covered=10 total=114
```

Paired comparability over the two saved seeds
(`automatic-coverage-20261028/compare/seed-7-state-none` vs `seed-7-uniform-none`):
`status=comparable_points`, DUT points 22/30 vs 21/30 (`hit_delta=-1`, one
left-only point), identical command count (35) and local ticks (41), and
`seed`/`time_budget`/`execution_budget`/`process_independence`/`fairness` all
`unknown`. No superiority is claimed.

Missing inputs always yield `unavailable` with no numeric field:
missing trace, incomplete measurement (with the exact missing file list), missing
original cache, unverifiable measurement, and the CLI exit code/JSON/summary all
agree.

## What the native script will prove once the lead runs it

`scripts/run_directed_irq_native.py` delegates the four executable cases to the
public `scripts/run_timer_irq_smoke.py` (two independent sessions of three
components each) and then re-derives every declared layer from the produced
journals with the same production joiners used by the tests. `summary.json`
carries explicit scope fields and `native_authority=false`.

```
# preflight only (nothing is started) — already run here:
# status=ready counts={'ready': 4, 'refused': 4, 'error': 0}
# native_run=false native_authority=false
PYTHONPATH=src python3 scripts/run_directed_irq_native.py \
  --config configs/scenarios/directed-irq-matrix.json --case <case> \
  --output <dir>/preflight --native --preflight

# executable native cases (frozen window; one process tree each)
PYTHONPATH=src python3 scripts/run_directed_irq_native.py \
  --config configs/scenarios/directed-irq-matrix.json \
  --case cross-protocol.apb-spi-cv32e20 \
  --output runs/directed-irq-native/apb-spi-cv32e20 --native \
  --cache runs/config-driven-20261028/cache

PYTHONPATH=src python3 scripts/run_directed_irq_native.py \
  --config configs/scenarios/directed-irq-matrix.json \
  --case cross-protocol.apb-spi-ibex \
  --output runs/directed-irq-native/apb-spi-ibex --native \
  --cache runs/config-driven-20261028/cache

PYTHONPATH=src python3 scripts/run_directed_irq_native.py \
  --config configs/scenarios/directed-irq-matrix.json \
  --case cross-protocol.wb-timer-ibex \
  --output runs/directed-irq-native/wb-timer-ibex --native \
  --cache runs/config-driven-20261028/cache

PYTHONPATH=src python3 scripts/run_directed_irq_native.py \
  --config configs/scenarios/directed-irq-matrix.json \
  --case cross-protocol.ahb-sha-cv32e20 \
  --output runs/directed-irq-native/ahb-sha-cv32e20 --native \
  --cache runs/config-driven-20261028/cache
```

Each case writes `summary.json` (`status` = `verified`/`failed`/`refused`/
`unavailable`, `derived_layers`, `missing_layers`, `evidence`, refusal with
stage), the delegate's `runner/` directory (program, artifacts, `original/` and
`fresh/` journals, `summary.json`), and `runner-command.json`. It reports
`verified` only when all of: one actual `cpu_external_irq_taken`, exactly one
`irq_group_delivery` frame joined to it with `attribution_status='unique'` and the
exact active source id, a real high external input sample, exactly one exact
nonzero serial certificate in both the original and the fresh session, the
source-verified CPU artifact, the declared-output mapping, and the delegate's own
`fresh_matches=true` with non-zero clean process exits.

The script's derivation was exercised here **without** running anything, by
replaying it over the four saved journals:

```
PYTHONPATH=src python3 -m pytest \
  tests/integration/test_directed_irq_matrix_config.py -q -k replays_saved_journals
# 4 passed — every declared layer derived, 6 clean process identities per case,
# runner result status=verified (historical journals, not a new native run)
```

The other four cases are refused with their declared code and exit 2; they are
never reported as passes:

```
PYTHONPATH=src python3 scripts/run_directed_irq_native.py \
  --config configs/scenarios/directed-irq-matrix.json \
  --case reset-then-irq --output <dir>/reset --native
# status=refused, refusal.code=no-public-native-reset-case-runner
```

## Blockers and required source changes (not implemented here)

Owner-facing, each with the exact place to change. Nothing under `src/` was
edited by this task.

1. `src/myfuzz/scenario/irq_serial_certificates.py`, `IrqSerialCertificates._decision`:
   a document with a nonzero decision serial but `irq_taken_pre == 0` is still
   accepted and can certify (verified: 1 certificate). Only
   `gpio_irq_dependency_evidence.GpioNativeIrqEvidenceConsumer._take` requires
   `irq_taken_pre == 1`. Hardening: require the acceptance flag for `_TAKE_KINDS`.
2. Same file, `_RESET_KINDS`: omits `'gpio_reset'`, which
   `GpioNativeIrqEvidenceConsumer.consume` and
   `ScenarioRunner._consume_dependency_event` both treat as a reset. A raw
   session `gpio_reset` does not clear serial pending (verified: certificate
   still produced). Today's runner journals carry `reset_barrier` first, so the
   clear happens in practice; nothing asserts it.
3. Same file: no reset-epoch monotonicity. After a `reset_barrier`, a
   decision+retirement pair re-stamped with the pre-barrier epoch certifies again
   (verified: 2 certificates). Live runs are protected by
   `ScenarioRunner._effective_inputs` (`IRQ group source epoch changed`) and
   `GpioConsumptionTracker.consume` (`epoch_without_advanced_reset`); the offline
   reducer has no floor. Suggested: a `reset_epoch` floor per
   `(execution_id, component)`.
4. `src/myfuzz/integration/saved_irq_group.py`, `frame_for_sample`: binds a
   member sample's epoch to its own reference rather than to
   `frame['target_epoch']`, so an old-epoch member sample can join a fresh-epoch
   frame offline. Suggested: compare `raw['reset_epoch']` with
   `frame['target_epoch']` as well.
5. Native case support, for the owners of the smoke runners:
   - reset: `scripts/run_cv32e20_irq_smoke.py` / `scripts/run_timer_irq_smoke.py`
     need a case that calls `ScenarioRunner.reset_all('cold_all')` between a real
     decision and its retirement (`runner.py` already emits `reset_barrier` and
     the per-component `cpu_reset`/`gpio_reset_resource`), re-arms the CSRs and
     observes a post-reset take at epoch ≥ 1 (`execute_once` variant plus
     `inspect_evidence` reset assertions).
   - exception: `myfuzz/integration/rv32_fixed_firmware.py` needs a
     trap-exercising program builder (illegal instruction / `ecall` with `mie`
     set) plus an `inspect_evidence` variant asserting no decision serial and no
     take on the trap path.
   - two-source: `scripts/run_timer_irq_smoke.py::timer_program` needs a
     two-window trigger sequence and `inspect_evidence` needs joint and
     unique-per-member expectations (both members are measured today, only the
     active one is ever triggered).
6. CPU-side IRQ receipt coverage: every saved offline measurement in `research/`
   and `runs/` is `component: peripheral`; there is no `cpu` measurement for a
   declared-IRQ prefix, so `scripts/measure_new_path_coverage.py` has no real
   input for it (declared unavailable in the matrix).
7. CV32E40P: `src/myfuzz/local_harness/cv32e40p_irq_receipt_contract.py` and its
   dispatch in `native_irq_receipt_contract.py` landed during this session; the
   gate now admits it for all three target protocols and the contract tests cover
   `irq_redirect_pre`/`irq_taken_pre`/`irq_ack_pre`/`irq_id_pre`/`irq_entry_pc`.
   No saved native declared-IRQ journal exists for it, so no case is declared
   `native_ready` for cv32e40p; one declared-IRQ run with a
   `configs/cpus/cv32e40p_rvfi_local` CPU profile and a
   `research/.../declared-irq-*` `config.json` would be needed.

## Explicit `unavailable` items

- Native reset barrier between a real decision and its retirement.
- Native synchronous-exception trace (no trap-exercising firmware exists).
- Native debug/NMI diversion trace.
- Native simultaneous two-source take (joint attribution).
- Native unique take for the second member of the shared group.
- `cpu_irq_receipt_prefix_coverage` (no saved `cpu` measurement).
- Fixed-time-point and online coverage; coverage AUC.
- Any SoC-level coverage claim.
- Any F5/F6, ISR-MMIO, storage-version or reward authority.

## Non-claims

- No native run was performed by this task, so no line of this document is a
  native pass.
- The four saved journals are historical evidence recorded by the public runner;
  they are used here to validate the new script's derivation, not as this task's
  result.
- The admission matrix is a preparation fact. An admitted row means the artifacts
  and sessions can carry the declared-output/native-CPU evidence; it says nothing
  about an IRQ take, a serial certificate or the DUT's behaviour.
- Coverage numbers describe saved offline replays of one generated component,
  with seed/budget/process-independence unknown. They are not a comparison of
  search tools.
