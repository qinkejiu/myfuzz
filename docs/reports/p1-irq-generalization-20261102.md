# p1 IRQ generalization: arbitrary links, an ordered clear, a CPU that takes a multi-bit entry (2026-11-02)

Status: **real RTL**.  New runs 9/9 + 9/9 + 2/2 + 3/3 with one expected negative,
and every historical F5/DMA/multi-target regression still green.  This report
covers only the IRQ/F5 increment.

Three questions were open after round3:

1. does the F5 link table really generalize past the tested timer+I2C pair and
   past one link per target?
2. is there a status/clear form this host does not have that a pinned device
   really states?
3. can a CPU with a multi-bit interrupt entry (CVA6 `irq_i[1:0]`) actually take
   the line, with a take witness that is not an ISR store?

All three are answered with real runs; the rest is refused with the exact RTL
and profile facts.

Full commands, full case lines, per-link tables and wall/per-case times:
`runs/p1-irq/README.md`.  Batch: `runs/p1-irq/run_all.sh`
(stdout + shared-script digests: `runs/p1-irq/batch.log`).  Tests:
`runs/p1-irq/tests.log`.

## 1. Arbitrary topology

The entry already numbered every declaring target's links in one global table;
the fixed-size assumption was the synthetic two-source row, which required
*exactly two* declaring targets.  It now exists whenever two or more single-link
targets declare F5, pairs the first two in declaration order, and leaves every
other target reachable through its own row.  The precise refusal changes shape
accordingly: with one declaring target it is
`unsupported-f5:both-needs-two-targets`; with a declaring target that owns more
than one link it is `unsupported-f5:both-needs-one-link-per-target` (the pair's
per-target read/clear counters cannot tell two links of one target apart).

* **Three targets, three links** (`runs/p1-irq/three-ip-f5`): timer, I2C and SPI,
  each declaring one link.  One case per global link plus the pair row.  The pair
  `[0,1]` triggers both devices in one case, the ISR reads both status words at
  their own addresses (`0x40001000`, `0x4000200c`), stores two results and
  performs the I2C clear; `both_members 0,1`, `both_targets 0,1`.  The third
  target's own link case is independent and reads `0x20002028`.
* **Three targets, four links** (`runs/p1-irq/three-ip-multilink`): the PULP timer
  declares two links (overflow at status 0, compare at status 8), I2C and SPI one
  each.  Each case selects one global link and the case line names the target and
  the status word; the pair row is refused by name.  This is the "more than one
  link per target in one process" case, and it proves the two timer links are not
  folded together: link 0 reads `TIMER0_COUNT` (`kind count`), link 1 reads
  `TIMER0_CMP` (`kind compare`).

The limit is stated in the summary and in the README: one CPU input, two ISR
cell sets, one link per pair member.  A three-way simultaneous assertion is not
supported and is not claimed.

## 2. The new clear form: an ordered two-write acknowledge

Candidates were a W1C status that holds low, an ordered multi-step clear, and a
read+write sequence.  The W1C candidate failed on the RTL: the only W1C
interrupt status this repository has a composed target for is OpenTitan
`rv_timer`'s `INTR_STATE`, and it re-sets while expired
(`rv_timer.sv:82-83` `hw2reg.intr_state0[0].de = intr_timer_state_de`;
`timer_core.sv:45` `intr[t] = active & (mtime >= mtimecmp[t])`), so a W1C there
cannot hold low and is not claimed.

The PULP I2C's acknowledge *is* an ordered two-write sequence, and the RTL says
so: `apb_i2c.sv:128` `wire iack = r_cmd[0];` (the acknowledge is the held
register bit `CMD[0]`) and `apb_i2c.sv:189-193`
`irq_flag <= (s_done | i2c_al | irq_flag) & ~iack;` with
`interrupt_o <= irq_flag && s_ien`.  The first write (`CMD=1`) clears the flag
and drops the level; the second (`CMD=0`) releases the held iack, so the device
is not left masking every later `s_done`.

Implemented as a declared ordered sequence (`clear_sequence` in the declaration
vocabulary, `irq_clear_sequence` as the executor's scenario spelling), bounded to
two steps because the ISR carries two clear cell pairs.  A build whose
declaration states no such sequence emits the historical ISR byte for byte; a
build that states one performs the second step gated on its own published
address.  The C++ classifier is step-aware: a clear write counts only when it
matches the *next* declared step, so a missing or reordered write becomes a
missing clear (and a trigger write), never an accepted one.

Evidence (`runs/p1-irq/two-step-clear`, 2/2): `clear_writes 2`,
`last_clear_data 0x00000000`, and the APB event stream shows the order after
`irq_take 212`:

```text
apb 246 write 0x00000014 0x00000001
apb 260 write 0x00000014 0x00000000
```

The second case passes, which is the check that the first case's second write
really released the device.  The negative (`runs/p1-irq/two-step-clear-negative`)
declares `[[20,0],[20,0]]`: `irq_takes 5`, the level stays high for 250 ticks,
`level_stuck 1`, one device reset, case `failed`.  A declared clear that does
not deassert the device is a recorded failure.

## 3. CVA6: a two-bit entry, one driven and taken bit

The packed AXI4 F5 refusal was "the host never drives `irq_i`".  It now does, and
the take is witnessed:

* **Entry.**  `irq_i` is 2 bits on the built model.  Bit 0 is the
  machine-external entry the profile declares
  (`mip_d[riscv::IRQ_M_EXT] = irq_i[0]`, `core/csr_regfile.sv:2073`); bit 1
  (supervisor external, `IRQ_S_EXT`) is held at constant 0 **by the profile**
  (`port_actions irq_i`, bits `[1]`).  The summary states
  `cpu_irq driven_bit0_machine_external` / `cpu_irq_bit1 not_driven`.
* **Witness.**  Not `rvfi_intr`: the scoreboard sets it on the interrupt cycle
  (`cva6_rvfi.sv:499-503`) but the interrupt entry is not a valid RVFI record
  (`valid = 0`, `cva6_rvfi.sv:490-497`), and the measured run had no valid record
  with intr bit 2 set while the core really entered the handler.  The witness
  this host observes is the core's own `mcause` readback: `0x800000000000000b`
  (interrupt bit, cause 11 = machine external), with `mstatus` MPP=3/MPIE=1 at
  the entry snapshot.  The F5 ISR clears `mcause` after the entry (build-level
  `IRQ_TAKE_CLEAR`), so each case's take is its own 0 -> interrupt transition;
  the summary states `clock_cpu_take_witness mcause_readback`.
* **Evidence** (`runs/p1-irq/cva6-f5`, 3/3): two F5 cases two cases apart, each
  with `irq_takes 1` and its own `irq_take <tick> mcause 0x800000000000000b`
  event; the F2 between them takes nothing.  The handler ran in both (ISR read at
  `0x40001000`), and the take evidence is the CSR state, not the store.
* **Refusal.**  F5 on this CPU is admitted only when the model exports the
  declared entry *and* the retirement face states a take witness; otherwise it is
  `unsupported-f5:cpu-irq-unwired:cva6_packed_axi4` (no entry) or
  `unsupported-f5:no-take-witness:cva6_packed_axi4` (entry, no witness).

## 4. Refusals kept, with the facts

* NMI: `unsupported-irq:nmi-uncomposed:ibex_rvfi_local:irq_nm_i=constant-0` and
  `unsupported-irq:nmi-uncomposed:cva6:no-declared-nmi-port`.  No pinned profile
  composes an NMI source; Ibex's input is held inactive by the profile, CVA6 has
  no NMI port.
* PLIC: `unsupported-irq:plic-not-composed:<cpu>:no-declared-interrupt-controller-endpoint`,
  with the RTL fact beside it: `rv_plic.sv:63-89` is a real claim/complete
  controller, but no component profile composes it (no bus/clock/reset binding)
  and no CPU profile declares a claim/complete target port.  A host-only OR is
  not a PLIC.
* Vector: `unsupported-irq:cpu-multibit-vector:ibex_rvfi_local:one-external-input:irq_external_i-width-1`
  for the one-bit entry, and
  `unsupported-irq:cpu-vector-partial:cva6:irq_i[1]=constant-0-not-taken:...` for
  the multi-bit port whose second bit the profile holds.  Neither is called a
  per-source vector.
* Active-low target output and W1C interrupt status keep their named refusals;
  the W1C fact above (rv_timer re-sets while expired) is the reason the "W1C that
  stays low" form is not claimed.

## 5. Regressions

The historical two-target pair with its two-source cases (11/11), the one-target
two-link timer (6/6), the single-clear I2C level (3/3), the PULP GPIO
read-clears with two cause bits (4/4), the TL-UL rv_timer F5 (4/4) and the packed
AXI4 F2-F4 path (3/3) all pass unchanged in the same batch.  An F5 record aimed
at a target with no F5 facts is refused by name
(`unsupported-f5:target-irq-semantics:apb3:...`) before any model runs.

## 6. Tests

`tests/fuzz/test_irq_generalization.py` (new, 18 pure-Python tests) pins the
global link numbering and pair row, the record arity/refusals, the two-links-on-
one-target rule, the ordered clear (accept, bound, read-step and ambiguity
refusals, every malformed shape), the shipped two-step scenario against the real
I2C register map, the CVA6 entry/witness contract, and the CVA6/Ibex refusal
facts.  `tests/fuzz/test_irq_declaration_expansion.py` was updated for the two
new declaration keys.  `runs/p1-irq/tests.log` is the run of the focused
suites (fuzz, composition, the F1-F6 entry, mixed targets, p0-1 IRQ/DMA,
target protocols, Wishbone IRQ) with their results.

## 7. Limits and open items

* One CPU interrupt input, no per-source vector; the two-source row has exactly
  two members (two ISR cell sets); the ordered clear has at most two writes.
* F5 target protocols with a real run remain APB3 and TL-UL.
* The CVA6 take witness depends on the ISR's `mcause` clear; a CPU whose
  firmware cannot write `mcause` would need another witness and is not claimed.
* Concurrent increments share the two scripts; this increment's hunks are listed
  in `runs/p1-irq/README.md` section H, and `runs/p1-irq/batch.log` records the
  shared-script digests before and after every command.
