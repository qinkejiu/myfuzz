# round3 IRQ: simultaneous two-source F5, read-clears, multi-bit status vector (2026-11-02)

Status: **real RTL**, 13/13 in the new combined session and every historical
regression still green.  This report covers only the IRQ/F5 increment: the
two-source (`both`) F5 case with real per-target attribution, one more real
clear method (PULP GPIO read-clears), a real multi-bit status vector (PULP GPIO
`INTSTATUS`), and named refusals for NMI, PLIC, a per-source CPU vector, an
active-low device output and a write-one-clear interrupt status.

What is proven: on the pinned Ibex OBI + PULP timer + PULP I2C composition, one
F5 case triggers **both** devices, the CPU takes their OR'ed external input, and
one ISR body reads both status words at their own addresses, stores both results
in two separate RAM cells and performs each declared clear (I2C `CMD=1`; the
timer declares none).  The host checks the two status reads, both stored values,
both declared clear facts, each member link's own IRQ edge and both final raw
levels.  This is **status-content attribution**, not a CPU vector: the CPU has
one 1-bit external input and no per-source vector.

Full commands, case lines, wall/per-case times: `runs/round3-irq/README.md`.
Batch: `runs/round3-irq/run_all.sh`.

## 1. The both mode

The global F5 link table keeps its historical physical rows (one per declared
device output, each with target/base/status/trigger/clear facts) and appends one
**synthetic** row when exactly two targets declare F5 and each owns exactly one
link:

* `index` = one past the physical links (2 in this scenario), `mode: both`;
* `members` = the two physical link rows, in target declaration order;
* `trigger_offsets` = both trigger sequences concatenated;
* `status_offsets`, `clears`, `cause_masks` = each member's own facts.

Anything else (three declaring targets, or a declaring target with two links)
keeps the single-link cases and states `f5.both_refusal` instead of inventing a
shape (`unsupported-f5:both-needs-two-targets`,
`unsupported-f5:both-needs-one-link-per-target`).

The record shape is the both index followed by **both** trigger sequences:
`F5:2:<timer CTRL,CMP,COUNT>:<i2c CTRL,TX,CMD>` — 7 words for this composition.
The historical 4-word single-link records are unchanged and still accepted in the
same session.  The record gate accepts both counts by name (`F5 needs 4 or 7
word(s)`), and a short both record is refused by count, never truncated.

The ISR is extended only when the image carries the both row:

* the both body publishes two status addresses, two result cells, two clear
  address/value pairs, the two declared cause masks, the expected serviced mask
  and a zero serviced mask;
* it writes both trigger sequences in member order, then waits on the serviced
  mask with the same bounded timeout as the historical wait;
* the ISR reads status 1 and stores result 1, clears source 1 only when its
  declared cause is in that read, then reads status 2 and stores result 2, clears
  source 2 the same way, and marks a source serviced when its declared cause is
  present (a member without cause bits is serviced by its own read);
* after the serviced mask reaches the expected value the both body withdraws the
  second address/mask/expected cells, so a later F1–F4 case cannot perform a
  stale second read or clear.  The stored result cells are kept for the host.

A build **without** the both row emits the historical boot, bodies and ISR byte
for byte: the additional cells and the second read are a both-build feature.
That is why the single-target multilink and I2C regressions below are
byte-identical to round 1 rather than merely equivalent.

### Host checks (C++ F5 pass, both branch)

The case passes only when all of these are real observations:

* `irq_takes >= 1`, `irq_edges >= 1`, `isr_flag == 1`, `wait_timeout == 0`,
  `level_stuck == 0`;
* `trigger_writes == sum(declared triggers)` and
  `clear_writes == sum(declared clears)`;
* for each member: its own link raised (`irq_link_edges[m] >= 1`) and its device
  output was high (`target_irq_high[t] >= 1`);
* for each member target: at least one read, the **last** read offset is that
  link's declared status offset, the stored result cell equals the last read
  data, the per-target trigger write count equals the declared count, the last
  trigger address/value are the declared last trigger, the per-target clear count
  equals the declared clear count, and a declared clear's address/value match;
* a declared cause mask is set in the stored result (`last_read & mask != 0`);
* each member link's raw final level (pulse or level) is low
  (`irq_link_last` bit clear).

The single-link branch is untouched, including the historical requirement that
the ISR read is the case's only target read.

`summary.json` states `f5.both` (row index, word count, members with bases,
status offsets, triggers, clears, cause masks), `f5.delivery` (one OR'ed input),
`f5.simultaneous_attribution` (observed, status content not a CPU vector),
`f5.status_vector` and `irq_advanced`; the summary line adds
`irq_both_cases <n>` only for a build with the both row.

## 2. Real evidence

`runs/round3-irq/fixed-both` (13/13) runs the both case three times between
single-link cases, then reads both status words through F2.  Cases 5 and 6 use
the historical pulse trigger (`CTRL=0`, `COUNT=0xffffffff`): the timer asserts
first, the CPU takes the OR'ed line twice, and each ISR entry reads both status
words.  Verbatim fields of case 5:

```
... record F5:00000002:00000000:00000000:ffffffff:000000c0:0000005a:00000010
    trigger_writes 6 ... irq_edges 2 ... irq_takes 2 wait_timeout 0
    isr_result 0x00000000 isr_flag 1 isr_read_addr 0x40001000
    isr_read_value 0x00000000 isr_read_register_kind count
    isr_cause unknown
    both_link 2 both_members 0,1 both_targets 0,1
    both_link_edges 1,1 both_trigger_writes 6 both_clear_writes 1
    both_level_final 0x00000000
    isr_result2 0x00000081 isr_read_addr2 0x4000200c
    isr_read_value2 0x00000081 isr_read_register_kind2 status
    isr_cause2 0x00000001
    target0_read_offset 0x00000000 target0_read_data 0x00000000
    target0_last_trigger_offset 0x00000000 target0_last_trigger_data 0xffffffff
    target0_clear_writes 0
    target1_read_offset 0x0000000c target1_read_data 0x00000081
    target1_last_trigger_offset 0x00000014 target1_last_trigger_data 0x00000010
    target1_clear_writes 1 target1_last_clear_offset 0x00000014
    target1_last_clear_data 0x00000001
```

Both device outputs asserted in the case: `target0_irq_high_ticks 1` (timer
pulse) and `target1_irq_high_ticks 84` (I2C level).  The OR'ed input was accepted
twice because the timer pulse asserts about one tick after `COUNT` and the I2C
completes about 49 ticks after `CMD`; each ISR entry reads both status words, and
the stored cells are the last entry's values.  The report does **not** claim both
outputs were high on one particular tick, and does not claim a CPU vector.

Case 7 is the aligned variant: the timer counter is enabled (`CTRL=1`,
`COUNT=0xffffffcd`) so both real outputs have asserted when the CPU takes the
OR'ed line **once** (`irq_takes 1`, `irq_edges 2`, `both_link_edges 1,1`); the
single ISR entry reads both status words (`target0_reads 1`, `target1_reads 1`),
stores `0x0000000f` (the timer count) and `0x00000081` (the I2C status with cause
bit 0), performs the I2C clear and leaves both raw levels low.  The host accepts
one or more accepted edges, so both variants are real; the report does not claim
the two outputs were high on one particular tick.

The historical batch `fixed-multif5` is 10/10 with every semantic field of cases
3–6 and the summary identical to `runs/round1-multi-f5/fixed-multif5-r3`; only
`ticks`, per-case `seconds` and the work counters differ because the shared
ISR/body grew for the both row, plus the additive `irq_both_cases 0` field.

## 3. Clear/polarity methods with real devices

### Read-clears: PULP GPIO `INTSTATUS` (proven)

`runs/round3-irq/gpio-cause` (3/3) reads `INTSTATUS` at `0x40000024` and gets
`0x1`; `clear_writes 0`, `isr_read_clears 1`, `status_after_read 0x0`, final
level 0.  The device's own held status is cleared by the read:

* `third_party/soc-pulp-apb-gpio/rtl/apb_gpio.sv:154` — read of
  `REG_INTSTATUS_00_31` clears `r_status[0..31]`;
* `:160` — the same for `REG_INTSTATUS_32_63`;
* `:650-660` — the read mux returns `r_status`;
* `:131-137` — per-pin edge/type detection; `:140-145` — `s_is_int_all` and
  `interrupt = |s_is_int_all`.

The profile is the declaration side of the same fact:
`configs/peripherals/pulp_gpio_causal_local/component_profile.json`, `INTSTATUS`
offset 36, `ro`, `side_effect: read_clears`.  `irq_declaration` now carries
`status_read_clears`, the header renders `IRQ_LINK_READ_CLEARS`, and an F5 line
whose status is read-clearing prints `isr_read_clears 1`; the historical
timer/I2C lines are unchanged (the field is printed only when it is true).

### Active-low: refused

Every composed target profile states `polarity: active_high` (timer overflow /
compare, I2C level, GPIO interrupt, SPI EOT).  No real target output is
active-low, so the link's invert path is not exercised and no active-low case is
claimed: `unsupported-irq:device-active-low:no-declared-target-output-active-low`.

### Write-one-clear interrupt status: refused

No composed APB3/AXI4-Lite target exposes a W1C **interrupt status** register.
PULP GPIO `PADOUTCLR` is `write_one_clears` but is an output register, not an
interrupt acknowledge (the scan ignores non-status/INT registers by name), and
OpenTitan GPIO `INTR_STATE` (W1C, `configs/peripherals/opentitan_gpio/
component_profile.json:601`) is a TL-UL endpoint this APB3/AXI4-Lite entry does
not instantiate.  Refusal:
`unsupported-irq:write-one-clear:no-composed-target-register-declares-write_one_clears`.

## 4. Multi-bit status vector (PULP GPIO, proven)

New `configs/behaviors/pulp_gpio_multibit_f5_pins.json` and
`configs/scenarios/inprocess-obi-apb-gpio-multibit-f5-pins.json` declare
`status_cause_bits: [0, 1]`, `INTEN(24)=0x3`, `INTTYPE_LOW(28)=0x5` (2'b01 rising
edge for pins 0 and 1), `PADOUT(12)=0x3`, with `PADDIR(0)=0x3` set by the
preceding F4 case.  `runs/round3-irq/gpio-multibit` is 4/4:

* F5 case: `apb_read_data 0x00000003`, `isr_cause 0x00000003`,
  `irq_cause_pins 0x00000003`, `inten_at_irq 0x00000003`,
  `isr_read_clears 1`, `status_after_read 0x0`;
* the following F2 read of `INTSTATUS` returns `0x0` — the two-bit status was
  cleared by the ISR read.

RTL: `apb_gpio.sv:131-137` (two-bit type per pin), `:140-145`
(`s_is_int_all = r_gpio_inten & r_gpio_en & edges`, `interrupt`), `:154/160`
(read-clears), `:650-660` (read mux).  The vector here is the **status word's**
content; the CPU has one external input, so no CPU multi-bit vector is claimed.
`f5.status_vector.declared_bits` is 2 for this run.

## 5. NMI / PLIC / CPU vector refusals

`advanced_irq_refusals(cpu_profile, target_profiles)` in the entry states, in
every summary's `irq_advanced` block, what the pinned profiles do not compose.
For the Ibex builds in this increment:

* `nmi`: `unsupported-irq:nmi-uncomposed:ibex_rvfi_local:irq_nm_i=constant-0`.
  `configs/cpus/ibex_rvfi_local/component_profile.json:~317-321` declares
  `irq_nm_i` as `"action": "constant", "value": 0` ("the SoC composes no NMI
  source ... `soc_ibex_beat_core.sv` drives 1'b0").  The RTL has the input but
  this composition drives it inactive, so there is no trigger→delivery→ISR path
  to exercise.  The helper returns `None` only when a profile really states a
  connected NMI input (unit-tested with a synthetic one).
* `plic`: `unsupported-irq:plic-not-composed:ibex_rvfi_local:no-declared-
  interrupt-controller-endpoint`.  No CPU profile or target exposes a PLIC
  endpoint.  The only PLIC in the tree,
  `third_party/cvw_upstream_reference/src/uncore/plic_apb.sv`, appears in the
  CVW source file list, but the composed CVW boundary is AHB-Lite and F5 is
  already refused there (`unsupported-f5:cpu-irq-unexported:ahb_cvw`).  No PLIC
  model is instantiated.
* `cpu_vector`: `unsupported-irq:cpu-multibit-vector:ibex_rvfi_local:one-
  external-input:irq_external_i-width-1`.  The profile's
  `processor.interrupts` endpoint has one field of width 1; `irq_fast_i`,
  `irq_timer_i`, `irq_software_i` and `irq_nm_i` are constants.  One external
  input means the CPU has no source number to vector on.
* The CVA6 build states its own facts (`nmi` no port, `plic` none) and F5 is
  refused with `unsupported-f5:cpu-irq-unwired:cva6_packed_axi4`; its profile
  exposes more than one interrupt bit but the host only drives machine-external
  and implements no vector path.

## 6. Negative controls

* `both-negative-no-start` (1/2, expected failure): the same 7-word both record
  with I2C `CMD=0`, so the transfer never starts.  The host reports
  `wait_timeout 1`, `isr_flag 0`, `both_link_edges 1,0`, `both_clear_writes 0`,
  `isr_cause2 0x0` — one source asserted, the other was never serviced, and the
  case fails instead of attributing a second source.
* `negative-unselected-assert2` (8/9, expected failure), refreshed round-1
  semantics: the I2C is asserted through three F4 writes and never selected; the
  following F2 case fails with `target1_irq_high_ticks 202`, `irq_takes 5`,
  `level_stuck 1`, summary `device_resets 1`.  The OR delivers the unselected
  real output, but the host reports the storm rather than crediting the source.

## 7. Regressions, tests, wall time

* `repro-multilink` 7/7 and `repro-i2c-level` 3/3: case and summary lines
  byte-identical to `runs/round1-multi-f5/repro-multilink-r5` and
  `.../repro-i2c-level-r5` after removing wall-clock fields (these builds have no
  both row, so the image and ISR are historical).
* `two-ip-f1f6` 6/6 byte-identical to `runs/round1-multi-f5/two-ip-f1f6-r2`.
* `fixed-multif5` 10/10 with identical semantic fields (counters/ticks differ).
* `gpio-cause` 3/3, `gpio-multibit` 4/4, `refusal-no-f5` 2/2,
  `axi4-regression` 3/3 (F5 refused by name).
* Tests: `PYTHONPATH=src:. python3 -m pytest tests/composition/
  test_multi_target.py tests/composition/test_inprocess_behavior.py
  tests/integration/test_inprocess_f1f6_entry.py -q` → **348 passed**.  New
  focused tests cover the both record/ISR mapping and pass condition, the
  multi-bit cause mask, and the named NMI/PLIC/CPU-vector refusals.
  `tests/fuzz/test_irq_declaration_expansion.py` (55 passed) was updated for the
  new `status_read_clears` key in the exact declared-link dict.
* Wall time of the final warm-cache batch: `fixed-both` 6.231 s total / 0.0088 s
  host loop / 0.00362 s summed per case (max 0.000695 s); `fixed-multif5`
  6.251 s; regressions 5.0–6.6 s except the CVA6 AXI4 run at 17.595 s (link
  rebuild).  Full table in the run README.

## 8. Ownership / hunks

Edited only the IRQ/F5 regions:

* `scripts/run_inprocess_f1f6.py`: new handler cells (`HB_STATUS2`,
  `HB_RESULT2`, `HB_CLEAR2`, `HB_CLEAR_VALUE2`, `HB_MASK1/2`, `HB_NEED`,
  `HB_SERVICED`, `HANDLER_BLOCK_BYTES 52`), `result_f5b` at result+28,
  `_and`/`_ori`, `f5_link_word_count`/`f5_record_word_counts`/`f5_link_table`/
  `f5_both_link`/`f5_both_selected`, `parse_record` both shape,
  `build_firmware` both body/handler and conditional historical emission,
  `render_bindings` `f5_both` and `IRQ_BOTH_*`/`IP_RESULT2_ADDRESS`/
  `IRQ_LINK_READ_CLEARS`/`IP_STATUS_READ_CLEARS`, `irq_declaration`'s
  `status_read_clears`, entry both-row construction, `correspondence` both
  branch and `_f5_both_mismatch`, summary `f5.both`/`status_vector`/
  `irq_advanced`/`simultaneous_attribution`, F5 case key/replay lists.
  `advanced_irq_refusals` and the named refusal prefixes.
* `scripts/inprocess_obi_apb_f1f4_spike.cpp`: `IRQ_BOTH_*` defaults/tables,
  `is_both_f5`, per-target read/trigger/clear counters, `selected_clear` both
  branch, record parsing and `word_count` for the both shape, case-end second
  result/address sampling and `irq_link_last`, the both F5 pass, the both case-line
  group and `irq_both_cases`, `IRQ_LINK_READ_CLEARS` + `isr_read_clears`.
* `src/myfuzz/composition/multi_target.py`: **unchanged** (the existing
  `targets_for_f5` global selection is what the entry uses; `target_for_f5` keeps
  its historical one-owner refusal).
* New: `configs/behaviors/pulp_gpio_multibit_f5_pins.json`,
  `configs/scenarios/inprocess-obi-apb-gpio-multibit-f5-pins.json`.
* Tests: `tests/integration/test_inprocess_f1f6_entry.py`,
  `tests/composition/test_multi_target.py`,
  `tests/composition/test_inprocess_behavior.py`, and the one-line expectation
  update in `tests/fuzz/test_irq_declaration_expansion.py`.
* Evidence: `runs/round3-irq/` (README, `run_all.sh`, 11 run directories, plus
  interim `probe*` runs kept for audit).

The shared scripts are untracked in this checkout (`git status` shows `??`), so
`git diff` does not list them; the hunks above are the complete set inside the
owned regions.  Other agents were editing the same tree (mixed-target support,
F1 trap, AXI4/CVA6 sections) during this work; every run was repeated after the
final change.  No `git reset/clean/checkout/stash` was used and no run or report
was deleted.
