# CVA6 advanced increment: a real trap/CSR witness and real RV64 F1 execution

Date: 2026-11-02
Scope: the same one pinned CVA6 (`cva6`, cv64a6_imafdc_sv39) on the same packed
AXI4 path, one PULP timer target, one host RAM, one in-process executor.  This
report claims exactly what `runs/round3-cva6/` shows: the missing RVFI witnesses
are now exported and read, one declared M-mode `ECALL` is really trapped and its
cause/CSR state/handler-stored words are compared, and ten real RV64I programs
retire and are compared at the record's own 64-bit width.  It claims no F5, no
F6, no coverage, no certificate, no replay, no CSR fuzz, and no privilege switch
beyond the one declared ECALL.

## 1. Baseline verified before anything changed

The parent's state was reproduced first, on the unmodified tree, with the
existing scenarios and cache:

| run | cases | result | retirements | retire_dropped | wall |
| --- | --- | --- | --- | --- | --- |
| F1 4/2/1 words + F2-F4 | 6 | 6 passed | 106 | 0 | 25.5 s |
| F1 fuzz (`--cases 20 --seed 61001`) | 20 | 20 passed | 327 | 0 | 23.2 s |

Those two directories (`runs/round3-cva6/repro-f1-f2f4`, `repro-f1-fuzz`) are
kept; the final runs are the ones in the table in §7.

## 2. The missing RVFI witnesses, and what the pinned source really states

`src/myfuzz/local_harness/rtl/cva6_rvfi_top.sv` now emits, with each retirement
record and unmodified:

| port | width | pinned source |
| --- | --- | --- |
| `rvfi_cause` | 64 | `rvfi_instr_o[i].cause <= ex_commit_cause` (`core/cva6_rvfi.sv:511`) |
| `rvfi_intr` | 64 | `rvfi_instr_o[i].intr <= rvfi_intr[i]` (`core/cva6_rvfi.sv:509`) |
| `rvfi_mode` | 2 | `(DebugEn && debug_mode) ? 2'b10 : priv_lvl` (`core/cva6_rvfi.sv:512`) |
| `rvfi_mcause` / `rvfi_mepc` / `rvfi_mtval` / `rvfi_mtvec` / `rvfi_mstatus` | 64 each | `rvfi_csr_o.<csr>.rdata` (`core/cva6_rvfi.sv:563-604`) |

Two semantic facts were read out of the pinned scoreboard instead of assumed,
and they are stated in the wrapper's own comment:

* **`intr` is not one bit.**  The scoreboard assigns it the constants `'b101`
  (asynchronous interrupt) and `'b11` (synchronous trap) and clears it on the
  next *valid* retirement (`core/cva6_rvfi.sv:498-509`).  Because the clear is a
  later non-blocking assignment that wins, a synchronous trap's own record
  carries `intr = 0`; the word reads non-zero on the **first retirement after an
  asynchronous interrupt**.  It is therefore emitted as the scoreboard's own
  XLEN-wide value, and the trap case does not read it as "this record trapped"
  — `trap` and `cause` do that.
* **The CSR readback is registered one edge.**  `rvfi_csr_o.<csr>.rdata` is an
  `always_ff` capture of the CSR, so at a sampled edge it holds the value from
  the cycle before: on the edge that *writes* the CSR it still shows the old
  value.  Two CSRs read on one edge are one consistent snapshot, which is why
  `mcause`/`mepc` are recorded together.  The trap's authoritative cause is the
  record's `cause`; the readback is the architectural state after it, and the
  firmware's own `CSRR` is the independent witness.

`scripts/run_inprocess_f1f6.py` binds the new ports (`CPU_RVFI_CAUSE`,
`CPU_RVFI_INTR`, `CPU_RVFI_MODE`, `CPU_RVFI_CSR_MCAUSE`, …) and states
`HAVE_RVFI_TRAP_WITNESS 1` only when the whole probe bundle is exported.  The
host prints the record's fields on the trap event and the readback as its own
`csr_trap` / `csr_mepc` event lines; a build without the witness still prints a
trap's cause as `unknown` and claims nothing.

## 3. The declared trap case (real exception, real handler, real CSR state)

Scenario `configs/scenarios/inprocess-cva6-axi4-timer-f1-trap.json` declares
`f1_trap_program: {cause: 11, words: 2}` and the submitted program is
`F1:00000073:00000013` — an `ECALL` followed by one `ADDI x0, x0, 0`.

**M-mode / CSR assumptions, from the pinned configuration:** CVA6 resets into
M-mode (`priv_lvl` after reset), the firmware's bootstrap writes
`mtvec = vector | 1` (vectored), sets `mie.MEIE`, `mstatus.MIE` and then jumps to
the main loop.  In vectored mode an *exception* enters at the vector base, so the
first vector entry jumps to the trap handler this image carries at
`ram_base + 0x600`; the machine-external interrupt slot (`vector + 44`) keeps its
F5 handler target.  The handler is part of the firmware image: no case writes it,
and the slot program cannot install or replace it.

The handler is a real M-mode exception handler:

```
CSRRS x10, mcause, x0      # the cause the core wrote
CSRRS x11, mepc, x0        # the trapping PC
LUI/ADDI x9, trap_cause    ; SW x10, 0(x9)
LUI/ADDI x9, trap_epc      ; SW x11, 0(x9)
CSRRW x0, mcause, x0       # clear the cause after storing it
ADDI x11, x11, 4           # resume past the ECALL
CSRRS x0, mepc, x11
LUI/ADDI x9, trap_flag ; ADDI x10, x0, 1 ; SW x10, 0(x9)
MRET
```

The three cells (`trap_cause`, `trap_epc`, `trap_flag`) are declared addresses
(`ram_base + 0x3080`), are seeded with `0xFFFFFFFF` before the case so a stale
word cannot pass, and are read back from the host's RAM model at case end.  The
`mcause` clear is the handler's own architectural write; it is what makes the
readback show a clean `0 → 11` transition for *each* trap case in one process
(the CSR is not reset between cases, because the CPU is not either).

**Observed** (`runs/round3-cva6/f1-trap/run.log`, case line quoted in full in
that directory's `README.md`):

| fact | observed | witness |
| --- | --- | --- |
| RVFI `trap` on the ECALL record | 1 | record field |
| RVFI `cause` | `0x000000000000000b` (11, M-mode ECALL) | record field |
| RVFI `intr` | 0 | record field (synchronous trap) |
| RVFI `mode` | 3 (M) | record field |
| CSR readback at trap entry | `mcause 0xb`, `mepc 0x12000` | `rvfi_csr_o` |
| handler's stored words | cause `0xb`, epc `0x12000` | the CPU's own `SW`s, read from RAM |
| handler flag | 1 | the CPU's own `SW` |
| handler's `mepc` advance | `rvfi_mepc_final 0x12004` | `rvfi_csr_o.mepc.rdata` |
| resume | `successor_pc 0x12008` (the installed return jump) | the next in-slot retirement |
| in-slot trace | 2 retirements, `fnv1a32:6907cf11` | host FNV-1a over the RVFI records |

`rvfi_order_monotonic 0` on that case is a real fact and is reported, not
suppressed: the wrapper's `rvfi_order` is the core's own MINSTRET plus the commit
lane, and the trapping ECALL does not advance MINSTRET, so the counter repeats
across the trap.  The case's ordering evidence is `prog_pc_ordered` (1) and the
reference trace, never the MINSTRET proxy.

`f1-trap-repeat` runs that program twice in one process: both cases pass, each
with its own `trap` + `csr_trap` + `csr_mepc` lines.

## 4. A separate RV64 F1 mode (real 64-bit execution)

`src/myfuzz/fuzz/f1_rv64.py` is a new module, separate from the RV32 gate and the
RV32 reference model (which are unchanged).  It admits exactly:

`LUI`, `ADDI`, `ADD`, `SUB`, `AND`, `OR`, `XOR`, `ADDIW`, `ADDW`, `SLLIW`,
`SRLIW`, `SRAIW`, `LD`, `SD` — straight-line, no branch/jump/CSR/system/FP/atomic
word, no compressed parcel.  `LD`/`SD` must use `x18` (the declared data-window
base), be 8-byte aligned and inside the declared 64-byte window; a word may read
only a register this same program wrote earlier, or `x0`/`x18`; the firmware's
`x8`/`x9`/`x18` may not be written.

The reference semantics are the RV64 ones (`ADDIW`/`ADDW`/`SRLIW`/`SRAIW`
sign-extend their 32-bit result into the 64-bit register), a store retires with
`rd = 0, wdata = 0` (RVFI's rule), and the trace hash is **FNV-1a 64** over the
four fields as 8-byte little-endian values (`f1_trace64` in the host,
`trace_hash64` in Python).  The host prints `prog_trace_hash64`,
`prog_last_wdata64` and `prog_last_pc64`, and in this mode it does **not** print
or compare the 32-bit digest at all.

`runs/round3-cva6/f1-rv64` runs ten generated programs (drawn, validated and
threaded through the evolving data window by
`runs/round3-cva6/generate_rv64_cases.py`) as fixed records in one process:
10/10 passed.  The 64-bit witness is not decorative — case 9 loads
`0x11111111deadbeef` with one `LD` and retires `ADDI x11, x11, -1` as
`0x11111111deadbeee`, a value that crosses bit 32.

The closed-loop F1 fuzzer is **not** claimed for RV64: `myfuzz.fuzz.strategy`
generates F1 programs through the RV32 generator, so the RV64 mode is offered as
fixed (generated-then-submitted) records only.  The ten cases were produced by a
script, validated by the same gate the entry uses, and then submitted through
`--records`; that is stated here instead of being called a fuzz batch.

## 5. F5: still refused, now by the missing wire

F5 remains refused, and the refusal name was corrected because the old one was
no longer true: the retirement face now *does* carry the trap/cause witness.
The refusal is
`unsupported-f5:cpu-irq-unwired:cva6_packed_axi4` (was
`unsupported-f5:no-retirement-or-trap-witness:cva6_packed_axi4`).  The exact
missing pieces, in the order they would be needed:

1. **Delivery.**  `f5_refusal_for_bus` returns for `axi4` before any link is
   declared, so `HAVE_IRQ_LINKS` is 0 and the tick loop's delivery block
   compiles out.  The AXI4 CPU's machine-external entry is the model's
   `rt_lh_p_7_0_0` (`irq_i[0]`, `mip_d[riscv::IRQ_M_EXT]`), driven through
   `CpuLink::set_irq`; nothing calls it from the F5 path.
2. **Take witness.**  The F5 pass rule requires `observation.irq_takes >= 1`,
   which the host increments from `CPU_IRQ_TAKE` (`probe_irq_taken_pre`).  CVA6
   exports no such port, so the take would have to be counted from the RVFI
   `intr` word on the first ISR-instruction retirement and/or the `mcause`
   `0x8000000b` readback — which is exactly the witness this increment added and
   is now available.
3. **Arming.**  The timer must be armed through the declared trigger writes with
   `mstatus.MIE`/`mie.MEIE` already set by the bootstrap (they are), and the ISR
   would have to read and clear the timer's own status; the current F5 firmware
   body and ISR already do that for the OBI path.

This report does not claim an interrupt was delivered or taken on CVA6.

## 6. Documented refusals (stated, not implied)

* No privileged-mode switch beyond the one declared M-mode ECALL; the handler
  runs in M-mode because the core resets there.
* No CSR fuzz: the only CSR accesses are the firmware handler's own
  `CSRRS`/`CSRRW`/`MRET` and the boot's `mtvec`/`mie`/`mstatus` writes.
* No second exception, no misaligned/faulting-instruction suite: the declared
  trap is one M-mode `ECALL` (cause 11), and any other cause is refused by name
  at scenario-validation time.
* No F6 (no DMA on this CPU path), no F5 (§5).
* No compressed parcel on CVA6, no RV64 compressed, no FP, no atomic, no RV64
  `SLL`/`SRL`/`SRA` immediate forms beyond the declared subset.
* No branch/jump/loop in the RV64 mode (the RV32 control-flow shapes remain
  RV32-only), and no RV32<->RV64 mixing in one scenario.
* The closed-loop F1 fuzzer remains RV32-only; the RV64 batch is fixed records.
* No coverage, certificate or replay claim anywhere.

## 7. Runs (all real, all saved under `runs/round3-cva6/`)

`runs/round3-cva6/run_all.sh` reproduces every row; each directory's `README.md`
section quotes the command, the summary line and every case line verbatim.

| run | cases | result | retirements | traps | ticks | wall |
| --- | --- | --- | --- | --- | --- | --- |
| `f1-f2f4` (required regression) | 6 | 6 passed | 114 | 0 | 1185 | 25.8 s |
| `f1-fuzz` (`--cases 20`) | 20 | 20 passed | 335 | 0 | 2811 | 25.2 s |
| `f2f4` (required regression) | 3 | 3 passed | 71 | 0 | 834 | 26.9 s |
| `fuzz-f2f4` (`--cases 8`) | 8 | 8 passed | 138 | 0 | 1388 | 26.5 s |
| `f1-trap` | 1 | 1 passed | 54 | 1 | 702 | 24.7 s |
| `f1-trap-repeat` | 2 | 2 passed | 85 | 2 | 967 | 27.2 s |
| `f1-rv64` (ten generated RV64I programs) | 10 | 10 passed | 180 | 0 | 1629 | 24.4 s |

`rvfi_retire_dropped` is 0 and the probe-bundle width is 6974 in every run; the
summary's `rvfi_projection` word now names the mode it belongs to
(`low32_of_rv64`, `trap_cause_csr_and_stored_words`, `native_rv64_record`), and
`rvfi_trap_witness cause_intr_mode_csr` is stated on all of them.

## 8. Regressions and tests

* Required CVA6 runs: F1 4/2/1-word cases + F2-F4 → 6/6; F1 fuzz → 20/20;
  F2-F4 → 3/3; F2-F4 fuzz → 8/8 (all above, on the final tree).
* `tests/local_harness/test_cva6_rvfi_trap_witness.py` (new) — the wrapper's
  cause/intr/mode and CSR ports, the header's `HAVE_RVFI_TRAP_WITNESS` and
  `TRAP_*_CELL` macros, the trap scenario declaration and its refusals, the
  firmware handler's instructions and the vector's exception entry, the record
  validator, the reference trace (`fnv1a32:6907cf11`, the value the real run
  printed), the host's checks and the run-log parser for both trap shapes and
  the CSR lines.
* `tests/fuzz/test_f1_rv64.py` (new) — encode/decode round-trip for all fourteen
  subset instructions, the refusal set, the RV64 semantics (sign extension,
  8-byte `LD`/`SD`, 64-bit `ADD`), the 64-bit hash, the generator, and the
  scenario/header declaration (RV64 scenario = 1, RV32 scenario = 0).
* Green on the final tree: the CVA6 local-harness selection (104 passed, 24
  subtests), `tests/composition/test_cva6_component_profile.py` (25 passed),
  `tests/local_harness/test_cva6_rvfi_retirement.py`,
  `tests/local_harness/test_cva6_rvfi_trap_witness.py`,
  `tests/fuzz/test_f1_rv64.py`, `tests/integration/test_inprocess_f1f6_entry.py`
  and `tests/integration/test_inprocess_axi4_cpu_analysis.py` (271 passed when
  run together).
* `tests/fuzz` as a whole: 1014 passed, 1 failed in
  `test_irq_declaration_expansion.py`, which is **not** this work: another
  agent's in-flight change added a `status_read_clears` key to the F5 IRQ
  declaration and its own test has not been updated yet.  Nothing in this
  increment touches `irq_declaration`, the F5 link table or the F6 path.

## 9. Shared-file hunks (the two shared scripts are untracked)

`scripts/run_inprocess_f1f6.py`:

* `AXI4_F5_REFUSAL` constant (name corrected) — §5.
* AXI4 field mapping: `CPU_RVFI_{CAUSE,INTR,MODE}` and
  `CPU_RVFI_CSR_{MCAUSE,MEPC,MTVAL,MTVEC,MSTATUS}`, `have_trap_witness`.
* Header: `HAVE_RVFI_TRAP_WITNESS`, `F1_RV64`, `F1_TRAP_PROGRAM`,
  `F1_TRAP_CAUSE`, `F1_TRAP_WORDS`, `TRAP_{CAUSE,EPC,FLAG}_CELL`,
  `TRAP_SENTINEL`.
* `build_firmware(..., f1_trap=None)`: the trap handler image, the vector's
  exception target, the cells' image and span, and the return fields.
* Run-log parsing: the witnessed `trap` shape, the `csr_trap`/`csr_mepc` lines,
  collected beside the counted event families (`CSR_EVENT_KINDS`) so the
  existing `counts`/`per_case` dicts are unchanged.
* `f1_declared_mode`, `f1_trap_mismatch`, `f1_rv64_mismatch`, the
  `correspondence(..., f1_mode=None)` parameter and its two call sites.
* `main`: the `f1_trap_program`/`f1_rv64` declaration checks and refusals, the
  trap layout, the record dispatch, and the mode-specific `f1_limit_text`.

`scripts/inprocess_obi_apb_f1f4_spike.cpp`:

* `F1_RV64`/`F1_TRAP_PROGRAM` defaults and `F1_TRACED` widened to include them.
* `f1_trace64` (FNV-1a 64) beside `f1_trace`.
* `f1_trap_gate` / `f1_rv64_gate` host shape gates and their use in
  `make_record` (the RV32 per-word loop is unchanged and still used for every
  other shape).
* The retirement block: the 64-bit trace hash update, the record's
  cause/intr/mode on the trap event, the per-tick `csr_trap`/`csr_mepc` readback.
* The F1 rule: `#if F1_TRAP_PROGRAM` kF1 rule, the "a trap fails the case" rule
  excepted for the declared one, the stored cells read at case end, the case-line
  fields (`trap_*`, `rvfi_*`, `prog_last_*64`, `prog_trace_hash64`).
* The summary: the mode's `rvfi_projection` word and `rvfi_trap_witness`.

`src/myfuzz/local_harness/rtl/cva6_rvfi_top.sv`: the record and port additions of
§2 (the pinned scoreboard, its two-lane queue and the order rule are untouched).

## 10. Environment note

Other agents were editing the same two shared scripts while these runs were
made.  Two runs failed with the entry's own guard
`in-process link inputs changed during compilation` (a source changed during the
Verilator link); both were rerun after the edits settled and the saved
directories are from clean runs.  No run was edited, and no artifact was
deleted.
