# CVA6 packed-AXI4: a real instruction-retirement observation, proven with F1

Date: 2026-11-02
Scope: one pinned CVA6 (`cva6`, cv64a6_imafdc_sv39) on the existing packed-AXI4
path, one PULP timer target, one host RAM, one in-process executor. This report
claims exactly what the saved runs show: instruction retirements of RV32IM
straight-line records, observed on the CPU's own RVFI record stream. It claims no
coverage, no replay, no certificate, no RV64/CSR/privileged execution and no F5.

## 1. What was missing and what was wired

The pinned CVA6 does export its retirement probes: `output rvfi_probes_t
rvfi_probes_o` (6974 bits) at `third_party/cva6_upstream_reference/core/cva6.sv:339`,
driven from `cva6_rvfi_probes` at `core/cva6.sv:1965`. A probe bundle is not an
instruction record, and the pinned `rvfi_probes_o` had no consumer: the generated
harness connected it to an internal wire (`dut_p_11` in the archived wrapper) and
nothing read it.

The record is produced by the pinned scoreboard `core/cva6_rvfi.sv`, which
recovers the **committing** uop's instruction word from its own issue/commit
scoreboard (`rvfi_instr_o[i].insn <= mem_q[commit_pointer[i]].insn`,
`core/cva6_rvfi.sv:496`) and derives trap/intr/cause from the commit stage's
exception path. Sampling the core's `instruction[0]` at commit time instead would
report the most recently *issued* word, which can belong to a younger uop than the
one committing; that shortcut was not taken.

`cva6_rvfi.sv` and its type packages are **not** in the core filelist
(`core/Flist.cva6` lists only `cva6_rvfi_probes.sv`), so compiling it into the
generated model would add a source to a pinned closure. It is instead Verilated as
a second model beside the run, linked like `axi4_processor_memory_adapter`:

| layer | object | file |
| --- | --- | --- |
| probe bundle | `rvfi_probes_o` (6974 bits) exported whole | `configs/cpus/cva6/component_profile.json`, port action `observe` |
| generated port | `rt_lh_p_11_6973_0` (runtime) / `lh_p_11_6973_0` (wrapper) | `src/myfuzz/local_harness/port_rendering.py` (existing `observe` disposition; no renderer change) |
| probe copy + clock | `CpuLink::ProbeAdapter` copies the words in the low phase and clocks the model on the link's one rising edge | `scripts/inprocess_axi4_host.h` |
| scoreboard | `cva6_rvfi` + a two-lane-to-one retirement queue | `src/myfuzz/local_harness/rtl/cva6_rvfi_top.sv` |
| build | `build_cva6_rvfi_adapter` (Verilator `-j 2`, its own `--Mdir`) | `scripts/inprocess_cva6_rvfi_build.py` |
| record read | `cpu_retirement.CPU_RVFI_*` ( = the `rvfi` model on this bus) | `scripts/inprocess_obi_apb_f1f4_spike.cpp` retirement block |
| discovery / enablement | probe-bundle export -> RVFI fields, `HAVE_RVFI_ADAPTER` | `scripts/run_inprocess_f1f6.py` |

Both models are clocked on the same edge: the probe words are copied from the CPU
model's port in every low phase (`CpuLink::drive`) and the scoreboard's clock is
toggled only inside `CpuLink::clock_edge`, so the scoreboard registers exactly the
probe bits the core presented at that edge. Reset is the CPU's own reset level
(`CpuLink::set_reset`).

## 2. Retirement semantics that were wired

* **Validity** — `rvfi_instr_o[i].valid` = `commit_ack[i] && !ex_commit_valid &&
  !commit_drop[i]`, or the environment-call exception case; `trap` =
  `exception && !cause[31]`. Nothing is inferred from a fetch, from an address or
  from the host's installed words.
* **Instruction word** — the scoreboard's `mem_q[commit_pointer[i]].insn` (a
  16-bit parcel is reported as `{16'b0, parcel}`; this subset admits no compressed
  word, so every admitted record is a whole 32-bit word).
* **Order** — the pinned `cva6_rvfi.sv` never assigns `rvfi_instr_o.order` (the
  field exists in the `RVFI_INSTR_T` macro and is never written), so the wrapper
  emits the core's own MINSTRET (`rvfi_csr_o.instret.rdata`, the architectural
  retired-instruction counter sampled on the same edge) plus the commit-lane
  index. That is a real CPU counter, not a host sequence number.
* **Two commit lanes** — `NrCommitPorts = 2` in this configuration, so a clock can
  carry two valid records. The wrapper holds them in a 4-deep queue and emits one
  record per clock, oldest first, which is the face the OBI/Wishbone CPUs expose
  and the F1 block already reads. Every emitted record is an unmodified
  `cva6_rvfi` record. If the queue could not keep up, a sticky `retire_dropped`
  is set and the host **fails the F1 case** instead of shrinking the count; it is
  0 in every run below.
* **History of the port** — an archived wrapper from the earlier CVA6 work
  (`runs/cva6-f1f4-20261031/generated-fresh-archived/processor/wrapper.sv`) shows
  the same `dut_p_11` wire with no consumer; that is the gap this change closes.

## 3. RV64 record, RV32 comparison (declared, not implicit)

CVA6 is RV64: `rvfi_pc_rdata` and `rvfi_rd_wdata` are 64 bits. The first admitted
F1 subset is RV32IM straight-line records (1..4 words) inside the 64 KiB image
window, executed by the 64-bit core. The host compares the **low 32 bits** of the
record with the RV32 reference trace, and the truncation is written out in one
place in the retirement block.

The width projection is a **declared scenario fact**
(`"f1_rv32_projection": true` in `configs/scenarios/inprocess-cva6-axi4-timer-f1-f2f4.json`),
not an implicit xlen coercion:

* the entry refuses the flag on a CPU that does not declare xlen 64, and on any
  bus other than the packed AXI4 retirement path;
* it builds one projected `RiscvProfile(32, {I, M}, alignment 4)` and hands *that*
  to the record validator, the reference trace and the fuzz program generator;
* a 64-bit CPU **without** the declaration is still refused by the F1 program
  gate (`the F1 trampoline program gate is RV32-only; the declared xlen is 64`),
  which is pinned by a negative test.

## 4. Entry changes (AXI4 F1 enablement only)

* `axi4_rvfi_probe_export(cpu)` returns the exported `rvfi_probes_o` row only when
  the whole 6974-bit bundle is present; a missing or narrower export returns None.
* `render_bindings`, AXI4 branch: with the bundle present, `have_writeback = 1`,
  `CPU_RVFI_PROBES` = the bundle's runtime port and
  `CPU_RVFI_{VALID,ORDER,INSN,PC_RDATA,TRAP,RD_ADDR,RD_WDATA}` = the scoreboard
  model's record ports; the header includes `Vcva6_rvfi_top.h` and defines
  `HAVE_RVFI_ADAPTER`, `RVFI_ADAPTER`, `CPU_RVFI_PROBES_WIDTH` (6974) and
  `CPU_RVFI_PROBES_WORDS` (218). Without the bundle the header states
  `HAVE_RVFI_ADAPTER 0` and no RVFI macro is emitted.
* `AXI4_F1_REFUSAL` is now applied only when the bundle is absent. `AXI4_F5_REFUSAL`
  is unchanged: F5 needs an interrupt delivered to `irq_i`, which this host holds
  low, so F5 stays refused by name.
* The plan states the truth instead of the old constant: `retirement_observation`
  is `rvfi:cva6_rvfi_probes`, `f1_program.status` is `offered`,
  `f1_program.projection` is `rv32im_low32_of_rv64`, and the F1 limit text adds the
  RV64->RV32 projection clause. The CVA6 scope notes now say the probe bundle is
  exported and the scoreboard turns it into records, and that F5 is refused.
* The build step compiles the scoreboard from the repository's pinned tree with
  every closure source byte-compared against the **generated model's own cached
  inputs**; the one file outside that closure (`core/cva6_rvfi.sv`) is named as
  such in `cva6-rvfi-build.json`.

## 5. Runs (all real, all saved)

Full commands, complete case lines, summary facts and per-case times are in
`runs/round1-cva6-rvfi/README.md`. New cache directory:
`runs/round1-cva6-rvfi-cache` (built with `MYFUZZ_BUILD_JOBS=2`); the pre-existing
`runs/round1-cva6-cache` was not modified beyond the additive cache/link entries
the entry itself writes.

| run | cases | result | retirements | rvfi_writebacks | retire_dropped | wall |
| --- | --- | --- | --- | --- | --- | --- |
| `f1-f2f4` (3x F1 + F2/F3/F4) | 6 | 6 passed | 106 | 57 | 0 | 48.8 s |
| `f2f4-rerun` (existing scenario) | 3 | 3 passed | 63 | 33 | 0 | 26.1 s |
| `f1-fuzz` (`--fuzz --cases 20`) | 20 | 20 passed | 327 | 178 | 0 | 23.0 s |
| `fuzz-f2f4` (`--fuzz --cases 8`) | 8 | 8 passed | 130 | 64 | 0 | 24.0 s |
| `baseline-f2f4` (pre-change) | 3 | 3 passed | 0 (not observed) | 0 | n/a | 44.4 s |

The F1 case facts (`runs/round1-cva6-rvfi/f1-f2f4/run.log`):

```
case 0 F1:2ab00693:29d1f0b7:00b5f5b3:00192023 prog_words 4 prog_retires 4
       prog_pc_ordered 1 prog_insns_match 1 prog_traps 0 prog_writebacks 3
       retire_pc 0x00012000 retire_insn 0x2ab00693 successor_pc 0x00012010
case 1 F1:2ab00693:29d1f0b7 prog_words 2 prog_retires 2 prog_pc_ordered 1
       prog_insns_match 1 prog_traps 0 prog_last_rd 1 prog_last_wdata 0x29d1f000
case 2 F1:2ab00693 prog_words 1 prog_retires 1 prog_pc_ordered 1
       prog_insns_match 1 prog_traps 0 prog_last_rd 13 prog_last_wdata 0x000002ab
```

Trace hashes derived from the saved log (`derive_trace_hash.py` pairs the
`rvfi`/`retire` lines and hashes the in-slot retirements with the host's own
FNV-1a over `(pc, insn, rd, wdata)`):

| case | record | in-slot retirements | trace hash |
| --- | --- | --- | --- |
| 0 | `F1:2ab00693:29d1f0b7:00b5f5b3:00192023` | 4 | `fnv1a32:91711564` |
| 1 | `F1:2ab00693:29d1f0b7` | 2 | `fnv1a32:c8540b4c` |
| 2 | `F1:2ab00693` | 1 | `fnv1a32:6ced2117` |

Case 0's four retirements, verbatim from the log: `pc=0x12000 insn=0x2ab00693
rd=x13 wdata=0x2ab`, `pc=0x12004 insn=0x29d1f0b7 rd=x1 wdata=0x29d1f000`,
`pc=0x12008 insn=0xb5f5b3 rd=x11 wdata=0x0`, `pc=0x1200c insn=0x192023 rd=x0
wdata=0x0` — the installed words, in address order, with the writebacks the RV32
semantics predict (and no writeback for the store).

`fuzz-f2f4` and `f1-fuzz` run the host `--quiet` (the entry's own fuzz mode), so
their case lines carry no per-tick `rvfi`/`retire` events; their evidence is the
per-case retirement facts on the case line plus the batch summary.

## 6. Unsupported scope (stated, not implied)

* **RV64 execution, CSRs, privilege, traps handlers** — not claimed. The admitted
  records are RV32IM ALU/load/store words; the projection compares low 32 bits.
* **Compressed parcels** — `have_expanded` stays 0; no
  `rvfi_ext_expanded_insn_valid` port is invented.
* **Branches, jumps, loops** — the pinned configurations used here declare
  straight-line programs only (`f1_program_words: 4`, no branch/jump/loop flag).
  The host block's control-flow flags belong to the concurrent control-flow work
  and were not touched.
* **F5** — refused by name
  (`unsupported-f5:no-retirement-or-trap-witness:cva6_packed_axi4`). The AXI4 host
  holds `irq_i` low, so no interrupt can be delivered and no ISR side effect may
  be read as an interrupt take. The RVFI record does carry `trap`/`cause`/`intr`,
  but no trap or interrupt case is exercised or claimed.
* **Bursts / AMO** — unchanged: the fabric is single-beat and `awatop` completes
  with an AXI error.
* **Coverage / replay / certificate** — not claimed anywhere. One F1 case states
  one program's retirement facts.

## 7. Tests

Green (all run in this tree, in the final state):

* `tests/local_harness/test_cva6_packed_axi4_runtime.py` — 3 passed
* `tests/local_harness/test_cva6_full_axi_gate.py`,
  `test_cva6_full_axi_observer.py`, `test_runtime_template_identity.py` — 40 passed,
  21 subtests
* `tests/local_harness/test_cva6_axi4_service_protocol.py`,
  `test_cva6_axi4_service_real.py` — 5 passed, 3 subtests
* `tests/local_harness/test_cva6_source_lock.py`,
  `test_declaration_review.py` — passed
* `tests/composition/test_cva6_component_profile.py` — 25 passed (updated: the
  ledger now classifies `rvfi_probes_o` as `observe` with no coverage loss, and
  the netlist leaf is the wire the wrapper drives)
* `tests/integration/test_inprocess_f1f6_entry.py` — 189 passed
* `tests/integration/test_inprocess_axi4_cpu_analysis.py` — updated and passing
  (`rvfi_probes_o` is `observe`, not `unconnected`)
* `tests/fuzz` — 977 passed (0 failed) in the final state
* `tests/integration/test_soc_real_cva6.py`, `test_cva6_axi_mmio.py`,
  `test_cva6_fetch_identity_hops.py` — passed
* New: `tests/local_harness/test_cva6_rvfi_retirement.py` — 14 passed (probe-bundle
  discovery incl. negative widths and a missing export, header binding with and
  without the bundle, the wrapper RTL's pinned-scoreboard/queue/width-check shape,
  the host's low-phase copy and same-edge clock, the entry's build wiring, and the
  declared-projection positive/negative pair).

Observed but not attributable to this change (concurrent work in the same tree):
`tests/integration/test_soc_source_locks.py` and
`tests/integration/test_cva6_campaign_saved_run_audit.py` failed in one run on
source-lock/elaboration-evidence and campaign-identity records of other
components (`picorv32_wb_irq_rvfi`, `zipcpu_wbdmac`, ...), none of which this
change touches; a broad `tests/local_harness` sweep I started was cut short by
the harness time limit at 37% with one failure in a non-CVA6 file. The
CVA6/RVFI-specific files all pass as listed above.

## 8. Concurrency notes / files touched

Owned files only; no DMA, IRQ/F5 target, multi-target, mixed-protocol or
`src/myfuzz/fuzz/*` edit, and no edit to the F1 flag macro block itself (the two
`HAVE_RVFI_ADAPTER`/`RVFI_ADAPTER`/`CPU_RVFI_PROBES_*` lines are added *between*
`HAVE_RVFI_EXPANDED` and `HAVE_APB_PSLVERR`, leaving every `F1_ALLOW_*` line
untouched).

Tracked changes (`git diff --stat`):

```
 configs/cpus/cva6/component_profile.json | 8 ++++----
 1 file changed, 4 insertions(+), 4 deletions(-)
```

New files (untracked in this tree; `runs/` is gitignored):

```
configs/scenarios/inprocess-cva6-axi4-timer-f1-f2f4.json
configs/scenarios/inprocess-cva6-axi4-timer-f1-fuzz.json
scripts/inprocess_cva6_rvfi_build.py
src/myfuzz/local_harness/rtl/cva6_rvfi_top.sv
tests/local_harness/test_cva6_rvfi_retirement.py
runs/round1-cva6-rvfi/  (README.md, derive_trace_hash.py, 5 runs)
```

Modified but untracked (so `git diff` cannot show them — hunks listed here):

* `scripts/run_inprocess_f1f6.py`
  * `axi4_rvfi_probe_export` + `CVA6_RVFI_PROBES_BITS/WORDS` beside the refusals;
  * AXI4 branch of `render_bindings`: bundle discovery and the seven `CPU_RVFI_*`
    record fields (`have_writeback = 1`);
  * header: `#include "Vcva6_rvfi_top.h"`, `HAVE_RVFI_ADAPTER`, `RVFI_ADAPTER`,
    `CPU_RVFI_PROBES_WIDTH/WORDS`;
  * refusals: AXI4 F1 removed only when the bundle is exported;
  * the declared `f1_rv32_projection` (validated, projected `RiscvProfile`) and its
    use at the four F1 consumer call sites (`validate_record`, two
    `correspondence` calls, `fuzz_collaborators`);
  * `fuzz_collaborators(..., f1_program_profile=None)` so the F1 generator runs on
    the declared projection;
  * plan: `retirement_observation`, `f1_program.status/reason/projection`,
    `f1_limit_text`, the AXI4 scope notes, and
    `result['cva6_rvfi_adapter']` (the adapter build evidence);
  * build: `build_cva6_rvfi_adapter(ROOT, ..., pinned_root=<model inputs>)` added to
    the link's extra archives/includes.
* `scripts/inprocess_obi_apb_f1f4_spike.cpp`
  * `#define cpu_retirement rvfi|cpu` after the AXI4 host include;
  * the retirement block gate is now `#if !CPU_BUS_AHB && (!CPU_BUS_AXI4 ||
    HAVE_RVFI_ADAPTER)`, with the 64->32-bit projection written out at its top and
    `cpu.CPU_RVFI_*` -> `cpu_retirement.CPU_RVFI_*` (6 sites, mechanical);
  * the RVFI model + `RvfiBridge` (drive/reset/clock) beside `CpuLink`, attached
    with `link.attach_probe_adapter(...)`;
  * probe-width check right after the first `eval_all()`;
  * one additive `&& !rvfi.retire_dropped` term in the F1 pass expression, under
    `#if CPU_BUS_AXI4 && HAVE_RVFI_ADAPTER`;
  * the AXI4 summary words: `retirement_observation rvfi:cva6_rvfi_probes`,
    `rvfi_bundle`, `rvfi_bundle_width`, `rvfi_scoreboard`, `rvfi_projection`,
    `rvfi_retire_dropped` (the old `none:cva6_no_rvfi_exported` remains the
    no-adapter branch).
  * the F1 block's *ordering/flags semantics* were not touched.
