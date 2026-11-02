# round1 multi-F5: two real APB3 IRQ targets in one unified session (2026-11-02)

Status: real RTL, 10/10 fixed cases passed; single-target F5 timer (two links,
7/7), I2C level F5 (3/3) and the two-IP F1-F6 batch (6/6) still pass.  No
coverage, certificate, replay or full-SoC claim is made.

## 1. What was added

The previous increment routed a second APB3 target by address but allowed only
one of them to declare F5 (`target_for_f5` refused a second declaring target
with `unsupported-f5:multiple-target-irq-sources`).  This increment keeps that
strict helper for old callers and adds the multi-target path:

* `src/myfuzz/composition/multi_target.py`
  * new `targets_for_f5(targets, behaviors)` returns every target that states
    all four F5 facts, in declaration order (the caller's own target mappings).
  * `target_for_f5` is now implemented on top of it and keeps its historical
    single-owner refusal and its error words; `single_irq_target` is unchanged.
  * module docstring updated to describe delivery through the host's OR instead
    of the old "one IRQ line, one owner" limit.
* `scripts/run_inprocess_f1f6.py` (F5/IRQ sections only)
  * the entry calls `targets_for_f5`, numbers every declaring target's links in
    one global table (`index`, `target_index`, `base`, status/trigger/clear
    facts), and refuses inconsistent arity cross-target with
    `unsupported-f5:irq-links-differ-in-arity`.  `f5_index` stays the *first*
    declaring target (so `build_layout`'s `irq_base`, `IP_F5_TARGET_INDEX` and
    every legacy field keep their meaning).
  * `parse_record` maps an F5 record's global link index through the table to
    the case's `target_index`; one-link declarations keep the old 3-word shape.
  * `build_firmware` publishes each global link's own `base + status_offset`,
    `base + clear_offset` and `base` trigger window; a link without `base`
    keeps `layout['irq_base']`, so a one-target image is unchanged.
  * `render_bindings` takes `f5_links` and renders one `IRQ_SOURCES` row per
    link, each sampling its own target (`g_ip_irq[target]`), plus
    `IRQ_LINK_TARGETS`, `IRQ_LINK_BASES`, `IP_F5_TARGET_COUNT` and
    `IP_F5_TARGET_MULTI`.  The legacy path (no `f5_links`) is untouched.
  * `correspondence` resolves the case's link to its target and checks the ISR
    read address against *that* link's base; the case line's `irq_link_target`
    is checked against the link's target (only printed for multi builds).
  * the summary states `f5.target_count`, `f5.multi_target`, every link, the
    OR delivery sentence, `status_registers`/`irq_causes` per link, per-link
    `irq_sources`, and the explicit `simultaneous_attribution: not_supported`.
  * F5 case-observation/replay key lists gained `irq_link_target`; limitations
    and `irq_wiring` were rewritten for the OR.
* `scripts/inprocess_obi_apb_f1f4_spike.cpp` (IRQ/F5 sections only)
  * `IRQ_LINK_TARGETS`/`IRQ_LINK_BASES` tables (with legacy defaults),
    `IP_F5_TARGET_COUNT`/`IP_F5_TARGET_MULTI` defaults.
  * `selected_clear(record, target, ...)` labels the clear write only when the
    completed target is the selected link's target.
  * the F5 pass condition requires the case's target to be the selected
    link's target; `isr_read_address` uses the link's base.
  * per-target `target_irq_delivered_ticks`; summary classifies
    `target<n>_irq` as `delivered`/`observe_only`/`none` from the link table and
    `target<n>_f5` from the trait, not from `IP_F5_TARGET_INDEX`.
  * a multi build prints `irq_link_target` on F5 case lines and
    `irq_link_targets 0:0,1:1` on the summary; single-target lines are
    unchanged.
* `configs/scenarios/inprocess-obi-apb-two-ip-timer-i2c-multif5-f1f6.json`:
  timer (`irq_o[0]` pulse, status offset 0, no clear) at `0x40001000` and I2C
  (`interrupt_o` level, status offset 0xc, cause bit 0, clear `CMD=1`) at
  `0x40002000`; ZipDMA control at `0x40003000`; RAM `0x10000..0x30000`.
* `runs/round1-multi-f5/`: scenarios, full case lines, `summary.json`, and the
  README with commands, evidence, refusals and wall time.
* tests: `tests/composition/test_multi_target.py` (selection +
  one-target compatibility + normalization of the new scenario) and
  `tests/integration/test_inprocess_f1f6_entry.py` (global link mapping,
  multi-target header tables, F5 correspondence for the selected target,
  one-target compatibility).  The three required suites pass:
  `PYTHONPATH=src:. python3 -m pytest tests/composition/test_multi_target.py
  tests/composition/test_inprocess_behavior.py
  tests/integration/test_inprocess_f1f6_entry.py -q` → **340 passed**.

## 2. Real RTL evidence

Command (exact):

```sh
python3 scripts/run_inprocess_f1f6.py \
  --config configs/scenarios/inprocess-obi-apb-two-ip-timer-i2c-multif5-f1f6.json \
  --cache runs/stage2-stepD2-cache \
  --output runs/round1-multi-f5/fixed-multif5 \
  --records 'F1:2ab00693,F2:40001000,F4:40001008:0fffffff,F5:0:00000000:00000000:ffffffff,F5:1:000000c0:0000005a:00000010,F5:1:000000c0:0000005a:00000010,F5:0:00000000:00000000:ffffffff,F2:4000200c,F3:00014004:0badf00d,F6:0110c000:08000000:deadbeef:12345678'
```

The same batch was re-run twice on later tree states while concurrent edits
continued (`runs/round1-multi-f5/fixed-multif5-r2`, `...-r3`); both reproduced
the same case and summary lines once wall-clock fields are removed.

Result: `summary observations_passed cases 10 ... failures 0`, `ip_count 2`,
`irq_sources 3`, `irq_target_links 2`, `irq_link_edges 2,2,1`,
`irq_link_targets 0:0,1:1`, `target0_irq delivered target0_f5 yes`,
`target1_irq delivered target1_f5 yes`, `irq_takes 5`, `level_stuck 0`,
`device_resets 0`.

Per target (from the four F5 case lines; full lines are in the run log and in
`runs/round1-multi-f5/README.md`):

| link | case | target | ISR read address | kind | status read / stored | cause | clear | take |
|---|---|---|---|---|---|---|---|---|
| 0 timer | 3, 6 | 0 (`0x40001000`) | `0x40001000` | count | `0x00000000` / `0x00000000` | unknown (no cause bits) | none (`clear_writes 0`) | 1 |
| 1 i2c | 4, 5 | 1 (`0x40002000`) | `0x4000200c` | status | `0x00000081` / `0x00000081` | `0x1` | `CMD(0x14)=1` once, `last_clear_data 0x1` | 1 |

Each F5 case moved only its selected target (`target0_reads/writes` vs
`target1_reads/writes`); the other target stayed at `0/0`.  Case 5 repeats the
I2C sequence and passes (the clear worked); case 7 then reads `STATUS=0x80`
(bit 0 clear).  Case 4/5 show `target1_irq_high_ticks 38`; case 3/6 show
`target0_irq_high_ticks 1` and `delivered_high_ticks 16` (the declared pulse
stretch), which is why device and delivered counts are reported apart.

`summary.json` adds the machine-readable declaration: `f5.target_count 2`,
`f5.multi_target true`, `f5.links` (both bases/offsets/clears),
`status_registers` (`count` at 0x40001000, `status` at 0x4000200c),
`irq_cause per_link`, `irq_causes ["unknown","observed"]`, and
`f5.simultaneous_attribution = not_supported: ...`.

## 3. Regression runs

| scenario | records | result |
|---|---|---|
| timer multilink F5 (single target, two links) | `F1:2ab00693,F2:00014000,F3:00014004:0badf00d,F4:40001008:0fffffff,F5:0:00000000:00000000:ffffffff,F5:1:00000000:00000003:00000003,F6:0110c000:08000000:deadbeef:12345678` | 7/7; case/summary lines identical to the pre-change baseline (`runs/round1-multi-f5/repro-multilink`) after removing wall-clock fields |
| I2C level F5 (single target) | `F5:000000c0:0000005a:00000010,F5:000000c0:0000005a:00000010,F2:00014000` | 3/3; identical to baseline (`repro-i2c-level`) |
| two-IP F1-F6 (single F5 target + observe-only I2C) | `F2:40001000,F4:40001008:0fffffff,F5:00000001:00000000:ffffffff,F2:40002008,F4:40002010:0000005a,F3:00014004:0badf00d` | 6/6; `target0_irq delivered`, `target1_irq observe_only`, `target1_f5 no`, `irq_sources 2` |
| no-F5 declaration (I2C without interrupt) | `F2:40000008,F4:40000004:00000001` | 2/2 F2/F4; `f5.status refused`, `f5.reason unsupported-f5:target-irq-semantics:apb3:source_port,source_bit_offset,trigger_writes,status_offsets`, `f5.target_count 0` |
| AXI4/CVA6 F2-F4 (F5 refused; compiles the AXI4 path) | `F2:00014000,F3:00014004:0badf00d,F4:40001008:0fffffff` | 3/3; `runs/round1-multi-f5/axi4-regression`. Its summary differs from the older `runs/round1-multi-ip/axi4-regression` baseline because another agent's CVA6 RVFI adapter landed concurrently (`retirement_observation rvfi:cva6_rvfi_probes`, `retirements 63`); the case counts and transfers are unchanged |

## 4. Stretch goal: simultaneous assertion, precisely refused

Not implemented and not claimed.  Reasons, each grounded in the executed
design:

1. **Record shape.** One F5 record is `<global link index>:<trigger values>`
   with one fixed arity (all links must declare the same number of trigger
   writes).  The timer and I2C need different trigger offsets/values, so one
   record cannot carry both sequences; a second shape was not invented.
2. **ISR cells.** The firmware body of the selected link publishes one
   `HB_STATUS`/`HB_RESULT`/`HB_CLEAR`/`HB_CLEAR_VALUE` set.  The ISR reads and
   clears exactly that one word; there is no second status/result cell and no
   second store.
3. **Delivery is real but not attributable.** Both target outputs are sampled
   every tick and OR'ed into the one CPU input.  The negative control
   `runs/round1-multi-f5/negative-unselected-assert2` starts the I2C through
   three F4 writes and never selects it: case 4 reports
   `target1_irq_high_ticks 170`, `irq_takes 5`, `target_index 0` (the ISR read
   the boot-published timer status), `level_stuck 1`, `device_resets 1`, and
   the batch fails.  That is the honest outcome: the unselected target's real
   output was delivered, but the host reports the storm and resets the devices
   instead of claiming who interrupted.

If a later increment adds a two-status ISR and a record carrying both trigger
sequences, simultaneous attribution becomes testable; until then the claim is
single-source-at-a-time.

Other refusals kept: mixed APB3/AXI4-Lite target protocols, multi-target pin
model, links with different trigger-write counts, and every F5 refusal this
entry already had (AHB, AXI4/CVA6, Wishbone vector, missing facts).

### Final revalidation

After the last concurrent edits landed, every run was repeated
(`fixed-multif5-r3`, `repro-multilink-r5`, `repro-i2c-level-r5`,
`two-ip-f1f6-r2`, `refusal-no-f5-r2`, `negative-unselected-assert2-r2`).
All case and summary lines are identical to the runs cited above once
wall-clock fields are removed; final `total_seconds`: 12.431 / 13.385 /
12.574 / 13.839 / 13.357 / 7.028 s respectively.

## 5. Wall time

`total_seconds` from `summary.json` covers Verilator elaboration/cache lookup,
the g++ link and the run; `run_seconds` is the host loop only.

| run | total | run | per-case |
|---|---|---|---|
| multi-F5 fixed (`fixed-multif5`, warm models) | 13.151 s | 0.0066 s | sum 0.0017 s, max 0.000322 s |
| multi-F5 fixed from a fresh cache (`fixed-fresh-cache`, 4 models built) | 23.906 s | 0.0072 s | identical lines |
| two-IP F1-F6 | 14.585 s | 0.0063 s | max 0.000212 s |
| timer multilink F5 | 12.638 s | 0.0057 s | max 0.000287 s |
| I2C level F5 | 11.664 s | 0.0059 s | max 0.000326 s |
| no-F5 refusal | 13.550 s | 0.0068 s | max 0.000166 s |
| AXI4/CVA6 F2-F4 (adapter rebuilt) | 23.849 s | 0.0213 s | max 0.0077 s |
| unselected-assertion negative control | 6.790 s | 0.0066 s | max 0.000331 s |

## 6. Concurrency caveat

Other agents were editing the same tree, including
`scripts/run_inprocess_f1f6.py`, `scripts/inprocess_obi_apb_f1f4_spike.cpp` and
the AXI4/CVA6/RVFI sections, while this work was in progress.  Two run
attempts failed transiently: one with `in-process link inputs changed during
compilation` (the C++ source changed during the g++ step), one with a syntax
error in the host script while its F1/AXI4 section was being edited.  Both were
repeated once the tree settled; every number above comes from the saved logs
and summaries under `runs/round1-multi-f5/`.  The F5/IRQ regions were edited
with targeted `edit` calls only; no other agent's section was modified.

## 7. Changed files / diff notes

This checkout has the following files untracked, so `git diff --stat` does not
list them (`git status --short` shows `??`):

```
?? scripts/run_inprocess_f1f6.py
?? scripts/inprocess_obi_apb_f1f4_spike.cpp
?? src/myfuzz/composition/multi_target.py
?? tests/composition/test_multi_target.py
?? tests/integration/test_inprocess_f1f6_entry.py
?? configs/scenarios/inprocess-obi-apb-two-ip-timer-i2c-multif5-f1f6.json
```

`runs/` is git-ignored (`.gitignore:18`), so `runs/round1-multi-f5/` is
untracked evidence.  Hunks in the shared scripts (all inside the owned F5/IRQ
sections):

* `scripts/run_inprocess_f1f6.py`: `targets_for_f5` import; new
  `f5_case_link`; `parse_record` F5 target mapping; `build_firmware` per-link
  base; `render_bindings` `f5_links` parameter, per-link `IRQ_SOURCES`,
  `IRQ_LINK_TARGETS`/`IRQ_LINK_BASES`, `IP_F5_TARGET_COUNT`/`_MULTI`, observed
  IRQ per declaring target; `correspondence` per-link base/target; entry global
  link construction and arity refusal; summary `f5.links`,
  `status_registers`, `irq_sources`, limitations; F5 key/replay lists.
* `scripts/inprocess_obi_apb_f1f4_spike.cpp`: link target/base macro defaults
  and arrays; `selected_clear` target gate (two call sites);
  `ip_has_f5`/`ip_irq_delivered`; per-target delivered ticks in the link
  sample loop and summary totals; F5 `isr_read_address` and target pass term;
  F5 `irq_link_target` case field; summary `target<n>_irq`/`_f5` and
  `irq_link_targets`.
