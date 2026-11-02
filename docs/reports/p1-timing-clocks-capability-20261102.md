# P1 timing: declared per-model clocks, the phase scheduler, and the CPU capability matrix (2026-11-02)

Status: **real RTL**. Evidence directory: [`runs/p1-timing/`](../../runs/p1-timing/README.md)
(`README.md` commands and per-case wall times, `run.sh` reproduction, `rows/` seven sessions,
`refusals/` four expected non-zero exits, `case-lines.txt`, `campaign.log`, `wall.log`).
This file is the report itself, kept next to the other P1 reports; the scope statement below is
the one the increment was held to. No coverage, certificate, replay or full-SoC claim is made.
Scope: the unified in-process host (`scripts/run_inprocess_f1f6.py`,
`scripts/inprocess_obi_apb_f1f4_spike.cpp`, `scripts/inprocess_build.py`'s timing
link) and the CPU capability documents/tests.  No target-protocol, IRQ/F5
semantics, DMA-route semantics, behavior schema or F1-trace bytes were changed.

## What existed before

* One host tick drove every model's clock.  `declared_clock()` read each
  artifact's clock schedule and refused differing `frequency_hz` unless the
  scenario set `assume_single_clock: true`; every timed model had to declare the
  same `half_period_ps` (`TIMED_HALF_PERIOD_PS`), and the timed scheduler was one
  half period for all models.
* The CPU profiles differ in exported signals, but there was no generated
  document stating, per profile, what the retirement/trap/IRQ face is and which
  flows the unified entry can run.  A CPU without a retirement face failed late
  in header generation; the F5/F6 acceptance counts (`irq_takes`) are only
  produced from `probe_irq_taken_pre` or a custom EOI vector.
* The DMA build refusals named the bus but not the F6 flow.

## What was implemented

### 1. Declared-rate normalization (`scripts/run_inprocess_f1f6.py`)

`phase_clock_plan(rows, assume_single_clock=False)` turns the ordered model list
(cpu, targets, dma) into one plan:

* every model keeps the "one simple clock" contract already enforced
  (`model_clock_rate`): one `clk`, `phase_policy all_low_then_half_period_toggle`,
  ratio 1, first rising at one fast tick;
* equal rates → `equal_rates` (ratio 1, one tick for all, as before);
* differing rates → `per_model_ratio`: `half_period_ticks = f_cpu / f_model`, and
  the model's level for grid step `s` is `(s / half) % 2` — all clocks start low
  and a model's first rising edge is exactly at its own half period.
  Non-integer divisors, a model faster than the reference CPU, a ratio above
  `MAX_PHASE_RATIO = 1024`, a timed contract that disagrees with the ratio, and
  a timed grid whose half period is not whole picoseconds are all refused by
  name with the exact rates/ps numbers;
* `assume_single_clock: true` keeps the historical one-tick fallback and says so
  (`assumed_single_clock`); timed models must still agree on one half period in
  that mode.

The plan is written to `clock_plan.json`, embedded in `summary.json` (`timing`),
and rendered as header macros (`CLOCK_PLAN_MODE`, `CLOCK_*_HALF_TICKS`,
`CLOCK_REFERENCE_HZ`, `CLOCK_REFERENCE_HALF_PERIOD_PS`, `CLOCK_GRID_PERIOD_PS`,
`TIMED_GRID_PS` replacing `TIMED_HALF_PERIOD_PS`).  `render_bindings` takes the
same plan as an optional argument, so header and saved evidence cannot diverge;
legacy callers/tests render the plan of the artifacts they passed.

### 2. Per-model phase scheduler (`scripts/inprocess_obi_apb_f1f4_spike.cpp`)

`set_ip_clock(level)`/`set_clock(level)` were replaced by
`apply_phase_boundary(bool drive_cpu)`: one grid step per boundary, each model
toggles only when its declared half period divides the step, in the declared
low-first order.  The startup reset loop (`edge()`), the devices-only reset
(`device_tick()`), the main tick's low/rising/high/falling points, and the packed
AXI4 path (targets/DMA only; the CPU's one edge stays with `CpuLink`) all use
it.  `TIMED_GRID_PS` is the one simulation-time step advanced per phase; a timed
model whose half period is R steps really has R grid steps of real time, which
is the timed contract its profile already declared.

Because a model's registered protocol outputs are read one tick after its rising
edge, the host now computes three per-model gates each tick
(`scripts/inprocess_phase_clock.h`):

* `trace` — a rising edge happens in this tick (request/trace handshakes are
  pre-edge facts; one sample per model cycle);
* `response` — the previous tick applied the rising edge that registered a
  response;
* `probe` — the post-edge probe sample can see a rise at the tick start or mid.

The gates are applied to the request/response handshake, the route handshake and
route trace, the APB3/AXI4-Lite/Wishbone/TL-UL trace counters, the pin probes,
and the DMA control/master handshakes.  A ratio-1 model gets all three on every
tick, so the historical loop is unchanged (verified below); a ratio-R model is
sampled once per its own cycle, so a held level is never counted twice.

Per-case `clockcase` lines and summary `clock_*` fields record the host's real
rising-edge counts; the case lines keep their historical bytes.

### 3. CPU take witness and F5/F6 capability gates

`cpu_irq_take_witness` selects the CPU-side witness from the generated artifact:
`probe_irq_taken_pre`, then a custom EOI vector, then `rvfi_intr`.  The OBI/
Wishbone retirement face now maps `CPU_RVFI_INTR` when the model exports it, and
the host counts an interrupt take from a valid retirement with `rvfi_intr` set
**only while the delivered interrupt level is asserted** (so an exception's
handler entry is not counted as an interrupt take).  The packed-AXI4 scoreboard
keeps its own existing `intr` counting.

`cpu_flow_witness_refusals` refuses F5 and F6 by name when no witness exists;
`cpu_dma_port_refusal` refuses F6 by name when the CPU bus has no DMA port or the
DMA model is not a Wishbone DMA.  The `summary.json` fields `cpu_take_witness`,
`f5.reason` and `f6.reason` state all three cases.

### 4. CPU capability matrix

`scripts/cpu_capability_matrix.py` renders every `configs/cpus/*` profile from
its generated artifact (the same renderer the entry uses) into
`docs/cpu-capability-matrix.md` (+ JSON with `--json`).  Missing exports are
`unknown`/`none` or the exact refusal; every flow cell is `runnable` or
`refused:<the entry's exact refusal>`.  BOOM/BOOM_IRQ elaboration refusals are
kept as honest rows (`compiler tree exceeds node limit`), as are ibex
`full-top-required`, rvx_core source-lock and the unsupported CPU kinds.

### 5. Declared rate variants and scenarios (no pinned profile edited)

New declared composition variants of the pinned PULP `apb_timer`
(`pulp_timer_irq` source: same RTL/revision/reset/pins, only the declared rate —
and, for the timed variant, `verilator_timing_mode: timing`):

```
configs/peripherals/pulp_timer_25mhz/{component_profile.json,README.md}
configs/peripherals/pulp_timer_10mhz/...
configs/peripherals/pulp_timer_10mhz_timed/...
configs/peripherals/pulp_timer_30mhz/...        (non-divisor refusal fixture)
configs/peripherals/pulp_timer_60mhz/...        (faster-than-CPU refusal fixture)
```

New scenarios:

```
configs/scenarios/inprocess-obi-apb-two-rate-timers-f1f4.json        50/25/10 MHz, two targets
configs/scenarios/inprocess-obi-apb-timer-rate-cv32e40p-f1f4.json    timed CPU 50 / untimed 25
configs/scenarios/inprocess-obi-timer-timed-ip-f1f4.json             untimed 50 / timed 10
configs/scenarios/inprocess-obi-apb-timer-rvfi-intr-witness-f5.json  F5 with rvfi_intr
configs/scenarios/inprocess-obi-apb-timer-no-rvfi-f2f4.json          no-retirement refusal
configs/scenarios/inprocess-obi-apb-timer-nondivisor-ratio-refusal.json
configs/scenarios/inprocess-obi-apb-timer-faster-model-refusal.json
configs/scenarios/inprocess-ahb-cvw-apb-timer-dma-refusal-f1f4.json  F6-named DMA-port refusal
```

## Exact hunks

`scripts/run_inprocess_f1f6.py`

* new module-level: `MAX_PHASE_RATIO`, `CLOCK_PHASE_POLICY`,
  `model_clock_rate`, `declared_half_period_ps`, `phase_clock_plan`,
  `clock_assumption_text`, `clock_plan_header`, `clock_plan_for_artifacts`,
  `cpu_irq_take_witness`, `cpu_flow_witness_refusals`, `cpu_dma_port_refusal`;
* `render_bindings`: optional `clock_plan=` parameter; the old inline
  timed-contract/`declared_clock`/rate refusal block replaced by the normalized
  plan; `CPU_TIMED_MODEL`, `TIMED_GRID_PS` and the `CLOCK_*` macros; rvfi_intr
  field detection in the OBI/Wishbone and AXI4 branches;
  `HAVE_RVFI_INTR_PORT`/`CPU_TAKE_WITNESS`/`HAVE_CPU_TAKE_WITNESS`;
* `main`: witness resolution (bus-aware, packed-AXI4 scoreboard included before
  target F5 declarations), `clock_plan.json`, F5 per-target witness override, F6
  witness refusal, `clock_plan` passthrough, `timing`/`cpu_take_witness`/
  `clock_assumption`/limitations text, and the AHB summary's address width now
  calls `ahb_beat_address_width(cpu.runtime_document)` instead of the
  `render_bindings`-local name.

`scripts/inprocess_obi_apb_f1f4_spike.cpp`

* default macros and `#include "inprocess_phase_clock.h"`;
* the phase scheduler (`kCpuHalfTicks`, `kIpHalfTicks`, `kDmaHalfTicks`,
  `phase_step`, per-model levels/rises, `ip_rise_pending`, `dma_rise_pending`,
  `apply_phase_boundary`), replacing `set_ip_clock`/`set_clock`;
* `edge()`, `device_tick()`, initial clock state, main-loop start/mid/end
  boundary application (including the AXI4 target/DMA branch and the CPU rise
  accounting at `link.end_tick()`);
* per-tick `ip_trace_now`/`ip_response_now`/`ip_probe_now`/DMA gates and their
  application to the request/response, route, protocol-trace, pin and DMA
  handshake sites;
* the `rvfi_intr` take count (guarded to the no-probe/no-EOI/OBI case);
* per-case `clockcase` line and baselines; summary `clock_*` fields and
  `clock_cpu_take_witness`.

`scripts/inprocess_build.py`: no change was needed.  Its timed link already keys
on `'driver_timing' in artifact.runtime_document`, so the new timed IP variant
and the timed CPU both link `verilated_timing.cpp` with `-fcoroutines`; the
untimed ratio rows do not.  Verified in the rows' `link.log`:
`ratio-untimed-cpu-timed-ip` and `equal-rate-cv32e40p-f1f6` contain both,
`ratio-untimed-two-targets` neither.

New: `scripts/inprocess_phase_clock.h`, `scripts/cpu_capability_matrix.py`,
`docs/cpu-capability-matrix.md`, `tests/integration/test_timing_capabilities.py`,
the five variant profile dirs, the eight scenarios, `runs/p1-timing/` (this
evidence).

Tests updated (expectations of the changed refusal names / tripwire):
`tests/integration/test_inprocess_f1f6_entry.py` (clock mismatch test now covers
normalization + non-divisor + bound + assumption; F6-named DMA refusals),
`tests/integration/test_inprocess_ahb_entry.py` (F6 name),
`tests/fuzz/test_new_ip_2_onboarding.py` (`targets[].profile` scanned; inventory
count 14 → 19 for the five declared variants).

## Results

All rows are in `runs/p1-timing/rows/`; the full case/clockcase/summary text is
in `runs/p1-timing/case-lines.txt`.  Summary:

* `ratio-untimed-two-targets`: 6/6 passed; plan `per_model_ratio`, cpu/target0/
  target1 = 318/159/64 rising edges (ratio 1:1/2:1/5), both targets' real APB3
  reads and writes in one session, 41-53-tick target latencies in ratio order.
* `ratio-timed-cpu-untimed-ip`: 4/4 passed; timed CV32E40P beside untimed 25 MHz
  target; `grid_ps 10000`, 209/105 cycles (ratio 2); F1 trap unknown, writebacks 0.
* `ratio-untimed-cpu-timed-ip`: 4/4 passed; untimed Ibex beside timed 10 MHz
  target (50000 ps contract = 5 grid steps); 233/47 cycles (ratio 5); timing
  runtime linked.
* `f5-rvfi-intr-witness`: 5/5 passed; F5 `irq_takes 1` counted from `rvfi_intr`
  while the interrupt level was asserted; `cpu_take_witness rvfi_intr`.
* `equal-rate-ibex-timer-f1f6` and `equal-rate-cv32e40p-f1f6`: 6/6 each, and the
  case lines are byte-identical to the P0-1 baselines (modulo `seconds`), so the
  timing change did not alter the timed/untimed equal-rate behavior.
* `ahb-cvw-refusals`: 3/3 F2-F4 passed; summary states F1/F5/F6 by name and
  `cpu_take_witness none`; case lines say `traps unknown`.
* Four refusal rows with exact text: no-retirement build, non-divisor ratio,
  faster-than-CPU model, AHB+DMA F6.

Wall times 8-14 s per row (cache hit for models, one link per row), host run
4.7-52 ms; per-case times are in `README.md#wall-time-and-per-case-time`.

Tests: the final combined run of `tests/integration/test_timing_capabilities.py`
(22), `test_inprocess_f1f6_entry.py` + `test_inprocess_ahb_entry.py` (220),
`tests/fuzz/test_new_ip_2_onboarding.py` (14),
`tests/composition/test_profile_contract.py` (26) and
`tests/local_harness/test_timed_simulation_driver.py` passed 289/289.  The
broader fuzz/local-harness batch (`_scratch/pytest_fuzz_local.log`) ran 2733
passed; its remaining failures are all `tests/composition/*`
supervised-elaboration tests that this sandbox refuses by pgid (the documented
`setsid` requirement in `runs/stage2-ahb-unified-20261101/README.md`), not timing
failures.

## Limitations / honest gaps

* No coverage, certificate or replay claim; no cycles are fabricated for the
  1 Hz DMA placeholder (it stays under the explicit `assume_single_clock`,
  exactly as before).
* The timed-IP direction is a timed *build* of RTL that schedules no delayed
  events; no checked-in peripheral RTL has delays.  The timed-CPU direction has
  real scheduled events (the passive CV32E40P monitor) and is the real timed
  evidence.
* The reference CPU must be the fastest model; a faster model is refused, not
  sub-stepped.  Non-integer rational ratios are refused, not approximated.
* The F5-with-`rvfi_intr` path is proven on CV32E20 (`inprocess-obi-apb-timer-
  rvfi-intr-witness-f5`); the no-witness F5 refusal cannot be exercised by a
  build in this tree because every CPU model that builds through the unified
  entry exports either a take probe or `rvfi_intr`, and every model without a
  retirement face is refused earlier for the F1 trace.  The gate itself is
  implemented in `cpu_flow_witness_refusals` and unit-tested.
* `assume_single_clock` remains a declaration, not a measurement: its rows say
  `assumed_single_clock`, and the host still toggles a 1 Hz-declared model on
  every tick there — that is the pre-existing, explicitly assumed behavior, not
  a claimed 1 Hz cycle.
