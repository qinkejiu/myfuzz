# IRQ level storm: turn a repeated level into a reported case failure

Date: 2026-11-02. Status: **applied and verified** on 2026-11-02. The fix below is in
`scripts/inprocess_obi_apb_f1f4_spike.cpp` and `scripts/run_inprocess_f1f6.py`; the
real negative control is `runs/round1-irq-storm/stuck/` (case 0 F5 failed with
`level_stuck 1`, `irq_takes 5`, `device_resets 1`, case 1 F2 passed, batch failed
with 2 recorded cases). This document is kept as the applied patch record, not as
an open plan.

One wording below was corrected after application: `frame_done = true` **does not
stop the case at the abort tick**. It refuses a new frame, while the case still
waits for the interrupted handler to store the mailbox command back to zero (see
`storm_waiting_mailbox`), so the next input cannot be overwritten by the old
handler. The per-case tick budget remains the bound if that store never happens.

## Reproducer

- `configs/scenarios/inprocess-obi-apb-pulp-i2c-level-stuck-f5.json` + `configs/behaviors/pulp_i2c_level_stuck_f5.json`:
  - PULP I2C level source, `STATUS[0]` cause, `clear_writes [[0x14, 0x10]]` (a write command, **not** iack).
  - `handler_wait_iterations 2047`, `case_tick_budget 80000`.
- Command: `python3 scripts/run_inprocess_f1f6.py --config ... --cache runs/round1-i2c-cache --output ... --records 'F5:000000c0:0000005a:00000010,F2:00014000' --max-ticks 300000`.
- Current result: `{"status":"failed","cases":0}`; `run.log` ends `tick budget exceeded for the case` at tick 80000, with repeated `irq_take`/handler reads. The case never reaches the case-end level check, so `level_stuck` is 0 and no case line is printed.

## Fix (host)

1. Header: add `#ifndef IRQ_TAKE_LIMIT #define IRQ_TAKE_LIMIT 4 #endif` near `IRQ_SOURCE_COUNT`/`IRQ_TARGET_LINK_COUNT`.
2. In the `#if HAVE_CPU_TAKE` block after `++observation.irq_takes;`:
   ```cpp
   if (observation.irq_takes > IRQ_TAKE_LIMIT) {
     bool level_high = false;
     for (std::size_t i = 0; i < irq_links.size(); ++i)
       if (i < unsigned(IRQ_TARGET_LINK_COUNT) && kIrqLinkLevel[i]
           && irq_links[i].last)
         level_high = true;
     if (level_high) {
       observation.level_stuck = true;
       level_stuck_recovered = true;
       storm_waiting_mailbox = true;
       frame_done = true;              // refuse a new frame; wait for the mailbox
       EVENT_STREAM << "level_stuck_abort " << tick << '\n';
       recover_devices();               // reported, not masked
     }
   }
   ```
   `recover_devices()` clears the level and the link state; the CPU leaves the handler.
   The case is already failed. `frame_done` alone does **not** finalize the case: the
   loop waits until the handler stores zero to the mailbox command word
   (`storm_waiting_mailbox`), and the per-case tick budget still aborts the batch if
   that store never happens. The accepted `stuck` run finalizes at tick 446, after the
   abort at tick 386.
3. Case finalize:
   - Do not throw `"CPU did not consume the mailbox"` when `observation.level_stuck` (the handler storm may leave the command word uncleared; the next install overwrites it).
   - `passed` for F5/F6 must include `!observation.level_stuck`.
   - Print `level_stuck 1` and keep `irq_level_final` (which may be 0 after the reset) so the reset and the storm are both visible.
   - The existing `if (observation.level_stuck) recover_devices();` after the case is fine but redundant; keep the reported `device_resets` count.
4. Python:
   - Add `level_stuck` to `CASE_OBSERVATION_KEYS['F5']`/`['F6']` and `case_document`.
   - `correspondence`: if `case.get('level_stuck')` is truthy, return `'F5/F6 declared level IRQ storm was not cleared'`.
   - `classify_case`: map `level_stuck` to `level_irq_left_asserted` (anomaly, not expected). Add it to the class table next to `state_contamination`.
   - `recovery_declaration`: name `level_stuck` as a second trigger of `devices_only_cpu_and_ram_retained` (the current timeout trigger stays).

## Acceptance (observed 2026-11-02)

- `runs/round1-irq-storm/stuck/`: `summary failed cases 2`; case 0 F5 `failed` with
  `ticks 446`, `level_stuck 1`, `irq_takes 5`, `device_resets 1`, `wait_timeout 0`;
  case 1 F2 `observations_passed` at tick 34. Batch status `failed` (one real failed
  case), not `host_error`/0 cases.
- Correct I2C level scenario (`configs/scenarios/inprocess-obi-apb-pulp-i2c-level-f5.json`):
  still 3/3 passed, `level_stuck 0`.
- IRQ multilink timer batch: 7/7; no behavior change for pulse sources.
- Pure-Python case-line test: a `level_stuck 1` line is refused by `correspondence`
  and classified as an anomaly (`tests/fuzz/test_irq_clear_cause.py`).
- `runs/round1-irq-storm/stuck-before/` keeps the pre-fix batch-abort log for
  comparison; it is not a passing run.

## Non-goals

- No change to level delivery for a correct clear.
- No change to pulse sources or DMA completion.
- No retry of the failed case; the next case starts after the reported device reset.
