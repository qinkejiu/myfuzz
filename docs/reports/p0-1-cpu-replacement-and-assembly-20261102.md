# P0-1 agent A: profile inventory, assembly/routing, CV32E40P replacement (2026-11-02)

Scope: one increment on one source tree. Three deliverables — (1) a written
component-profile contract with focused tests, (2) a verified multi-IP assembly and
address-routing session, (3) a new CPU replacing Ibex in the unified entry. All
numbers below come from real Verilator RTL runs; nothing claims coverage, a
certificate or a replay, and a fetch is never counted as a retirement.

Evidence: `runs/p0-1-cpu/` (`README.md`, `run.sh`, `campaign.log`,
`case-lines.txt`, one directory per row). Contract: `p0-1-component-profile-contract.md`.

## 1. Profile inventory (contract + tests)

`docs/reports/p0-1-component-profile-contract.md` lists, field by field, what the
unified entry and the composition layer consume from a CPU, an MMIO IP and a DMA
profile, and the name each missing field is refused under. It reuses the existing
`component_profile.v1` loader and the existing declarations; no new schema was
introduced.

Focused tests: `tests/composition/test_profile_contract.py` (26 tests).
- a minimal CPU, MMIO IP and DMA profile each normalizes through
  `load_component_profile`;
- every checked-in CPU profile named in the replacement/regression work and every
  checked-in IP/DMA profile still normalizes and keeps its masters/registers;
- 15 missing-field refusals are asserted by name (`unsupported-profile-schema`,
  `unknown-profile-field:<key>`, `profile-clock-required`,
  `cpu-profile-requires-cpu-contract`, `invalid-cpu-xlen`,
  `cpu-master-endpoints-required`, `invalid-endpoint-function`,
  `endpoint-protocol-required`, `peripheral-profile-requires-address`,
  `address-window-not-power-of-two`, `address-alignment-not-power-of-two`,
  `invalid-interrupt-polarity`, `invalid-interrupt-domain`,
  `interrupt-pulse-width-required`, `cpu-profile-must-not-declare-mmio-address`);
- the timing mode is an optional capability (present only when declared);
- a CPU model without an `rvfi_trap` export is read as “no trap claim”, and an
  ambiguous export is refused;
- a three-target declaration normalizes, routes each window, and refuses overlap /
  duplicate names / duplicate active ids by name.

## 2. Assembly and address routing

No new routing code was needed: the existing `declared_targets` /
`target_windows` / `route_address` path and the entry's per-target artifact loop
built every declared target, and the generated header's per-target traits carried
the protocol. What was verified with real runs:

| row | declaration | result |
|---|---|---|
| `three-ip-timer-i2c-spi` | PULP timer + PULP I2C + PULP SPI, three `targets` rows, one OBI CPU | 9/9 `observations_passed`; `target_index` 0/1/2 per case; each target's own counter group moves only for the routed case; F5 stays on the timer |
| `cv32e40p-three-ip` | the same three IPs behind the replacement CPU | 8/8; the CPU swap changes no address or record |
| `mixed-apb3-axi4lite` | APB3 timer + AXI4-Lite axiluart | 6/6; per-case `target_protocol` states `apb3` or `axi4-lite` |

Each row's `target_windows`/`target_protocols` block lists the three windows and
their own protocols, and the per-case `target_index` plus the per-target counters
are the routing evidence. (Every summary also states
`combination_specific_branches none`; that word is the entry's own declaration, so
the report does not treat it as a computed check — the structural argument is that
the host dispatches on the generated `IpTarget<N>` traits and the entry/host
contain no CPU-name × IP-name comparison outside bus-kind refusal strings.) A combination outside the entry's protocol support keeps its named
refusal: the three-IP rows declare no DMA, so F6 is refused with
`unsupported-f6:no-dma-model:APB`. One structural limit the entry still enforces
generically is `unsupported-pins:multiple-targets` (the 32-bit pad *model* is a
one-target feature); none of the three declared targets uses it — their serial pins
are declaration-driven fixed inputs.

## 3. The CV32E40P replacement

`configs/scenarios/inprocess-obi-apb-cv32e40p-timer-zipdma-f1f6.json` is the
Ibex timer+ZipDMA declaration with its `cpu_profile` line changed to the pinned
`cv32e40p_rvfi_local` profile. It runs **F1–F6, 6/6 `observations_passed`**:
F1 retires 33 (program `prog_retires 1`, order and installed-word match);
F2/F4 hit the timer through the APB3 bridge; F5 delivers the timer's real `irq_o`
to `irq_i[11]`, takes the interrupt (`irq_takes 1`, `isr_result 0x10`); F3 writes
RAM; F6 moves four words with the ZipDMA (`dma_reads 4`, `dma_writes 4`,
`ctl_status 0x40`, `isr_result 0x40`).

**No CPU profile was edited.** `cv32e40p_rvfi_local` is pinned by
`cv32e40p_rvfi_contract`/`cv32e40p_irq_receipt_contract` (profile sha256
`fc070f67…`, source-union hash) and by the closure lock; the replacement is a new
scenario over that pinned profile. The scenario diff against the Ibex declaration
is `name`, `description`, `notes` and `cpu_profile` — nothing else.

Two honest blockers had to be cleared, and both fixes are generic:

1. **Timed model.** The profile declares `capabilities.verilator_timing_mode:
   timing` because its passive official monitor needs real delayed edges
   (`assign #0.01 clk_i_d = clk_i`) and delayed tasks (`#1`). The entry refused
   every timed model (`unsupported: timed models require a timing scheduler`) and
   the host link did not carry the timing runtime. Added:
   - entry: the timed artifacts' own `driver_timing` contracts are collected; a
     half-period disagreement and a timed model on the packed-AXI4 clock path are
     refused by name; the header states `CPU_TIMED_MODEL` and
     `TIMED_HALF_PERIOD_PS`;
   - host: `timed_advance_to()`, the same phase contract the models' own generated
     driver uses (low phase advances half a period and evaluates every scheduled
     event in time order; the rising edge is on the boundary; the high phase does
     the same, so the delayed monitor edge has really run before the host samples
     the retirement face; the falling edge is the next tick). Bounded at 65536
     evaluations per phase, requires 1 ps context precision, refuses an event in
     the past. Untimed builds (`CPU_TIMED_MODEL 0`) execute the previous code path
     unchanged.
   - build: the host link adds `verilated_timing.cpp` and `-fcoroutines` only when
     a linked artifact is timed, so untimed link commands and cache keys are
     byte-identical.
2. **No trap bit in the retirement face.** The pinned local top assigns only
   `rvfi_valid/rvfi_order/rvfi_insn/rvfi_pc_rdata` — there is no `rvfi_trap`, no
   `rvfi_rd_*` and no `rvfi_intr`. Rather than fabricating a zero, the entry now
   reads the model's real export (`cpu_rvfi_trap_port`) and states
   `HAVE_RVFI_TRAP_PORT`; the host prints `traps unknown`, `prog_traps unknown`
   and `trap_evidence unobservable`, never counts an unobserved trap, and skips
   only that assertion. The F1 record gate still requires the retirement count,
   address order, installed-word match and (for multi-word programs) the reference
   trace. With the port present nothing changes — verified by the byte-identical
   Ibex case lines and the trap-capable CV32E20 regression (which still prints
   `traps 0`).
3. One consequence of (2): a CPU with no `rvfi` order/writeback pair prints no
   `rvfi` event line, so the event layer now counts the host's own `retire` lines
   (beside `EVENT_KINDS`/`counts`, not inside them) to state that the retirement
   family was observed, and a `traps unknown` case line makes the trap family
   `unobservable` instead of `missing`. `counts`, `lines` and every existing event
   test's expected values are untouched.

The CV32E20 RVFI + native-IRQ-adapter variant (`cv32e20_profile_irq_adapter`,
F1–F6 6/6) is kept as a trap-capable regression, not as the replacement claim.

A closed-loop batch on the same timed model (`--fuzz --cases 8 --seed 1`) reports
`fuzz_completed`, 8/8 passed, 51 distinct features, in the same process with no
rebuild or reset. It also found one generic robustness defect outside the entry:
the pinned monitor prints a banner at time 0 whose trailing newline is a blank
line, and the closed-loop log writer indexed the first token unconditionally;
`src/myfuzz/fuzz/session.py` now writes a token-less line through instead of
raising.

## 4. Regression: the default path is unchanged

`runs/p0-1-cpu/rows/ibex-timer-f1f6` and the pre-increment
`runs/p0-1-cpu/repro/ibex-timer-single` were compared line by line:
`diff` over the case lines (after removing the per-case `seconds` field) is empty.
The same holds for the mixed-target and CV32E20 rows' structure. Test suites run:

```
PYTHONPATH=src:. python3 -m pytest tests/composition/test_multi_target.py \
  tests/composition/test_inprocess_behavior.py \
  tests/integration/test_inprocess_f1f6_entry.py -q     # 349 passed
PYTHONPATH=src:. python3 -m pytest tests/composition/test_profile_contract.py -q  # 26 passed
PYTHONPATH=src:. python3 -m pytest tests/integration -q -k inprocess               # 723 passed
PYTHONPATH=src:. python3 -m pytest tests/fuzz -q                                  # 1015 passed
```

One concurrent-tree failure is not this increment's: `tests/composition/
test_ibex_component_profile.py` now counts 20 `observe` dispositions where its
expectation says 25, because another agent added `direction`/`width` to the
`processor.interrupts` field of `configs/cpus/ibex_obi_local/component_profile.json`
(git shows exactly that 2-line change; no file this report touches is involved).

## 5. Shared-script hunks (the scripts are untracked)

| file | hunk |
|---|---|
| `scripts/run_inprocess_f1f6.py` | `cpu_rvfi_trap_port()` helper; `render_bindings` trap-port/`HAVE_RVFI_TRAP_PORT`; timed-contract collection + `CPU_TIMED_MODEL`/`TIMED_HALF_PERIOD_PS`; generated `IpTarget::next_time_slot()`; `summarize_events` retirement/trap evidence; F1 `prog_traps` tolerance (2 sites) |
| `scripts/inprocess_obi_apb_f1f4_spike.cpp` | timed scheduler + two phase advances in `edge()` and the main tick; `timed_events()` gate now untimed-only; `HAVE_RVFI_TRAP_PORT` guards on both trap reads and the pass/fail check; `traps`/`prog_traps`/`trap_evidence` unknown words; `IpTarget::next_time_slot`; `#ifndef` guards on `IP_MODEL_TYPES`/`IP_MODEL_INSTANCES`; `HAVE_RVFI_TRAP_PORT` default |
| `scripts/inprocess_build.py` | conditional `verilated_timing.cpp` + `-fcoroutines` on timed links |
| `src/myfuzz/fuzz/session.py` | a token-less log line (model banner) is written through instead of raising `IndexError` |

New files: two CPU scenarios (`inprocess-obi-apb-cv32e40p-timer-zipdma-f1f6`,
`inprocess-obi-apb-cv32e40p-three-ip-timer-i2c-spi-f1f6`), two assembly scenarios
(`inprocess-obi-apb-three-ip-timer-i2c-spi-f1f6`,
`inprocess-obi-apb-cv32e20-irqadapter-timer-zipdma-f1f6`),
`tests/composition/test_profile_contract.py`, the contract document, this report
and `runs/p0-1-cpu/`. No existing run or doc was deleted, and no IRQ/DMA-link
section was edited.

## 6. Limits

- The CV32E40P local top exports four RVFI fields: F1 states `traps unknown` and
  no writeback evidence; `rvfi_writebacks 0` is the missing port, not a measured
  zero.
- The boot address (`0x10000` vs Ibex's `0x10080`) comes from the profile's pinned
  formula; the firmware places its bootstrap at `layout['boot']` for every CPU, so
  no image is special-cased.
- The three-IP rows declare no DMA; F6 there is a named refusal, and the six-flow
  rows keep the existing ZipDMA declaration.
- Wall time per row is dominated by the one-time Verilator build/link of the model
  set; the timed CV32E40P run itself is ~10 ms for six cases.
- That the entry built a combination is not a proof that its protocol mix is
  semantically complete; an unsupported protocol or window still keeps its named
  refusal.
