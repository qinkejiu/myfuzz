# F1 control flow: proven JAL/JALR, a bounded loop, compressed control/memory

Date: 2026-11-02.  Increment: fourth F1 program-space expansion, after the
address forms (`runs/round1-f1-a/`), strictly-forward branches
(`runs/round1-f1-b/`) and packed compressed parcels (`runs/round1-f1-c/`).

## What was built

| File | Change |
|---|---|
| `src/myfuzz/fuzz/rv32_program.py` | JAL/JALR decoding and per-word rules; `control_flow_analysis` (whole-image target resolution, canonical bounded-loop proof with a static trip count, exact retirement bound, CFG); jump execution and the static step bound in `run_program`/`reference_run`; `generate_jump_program`, `generate_loop_program`, `mutate_control_program`. |
| `src/myfuzz/fuzz/rv32_compressed.py` | `CompressedPolicy(control, memory)` (default = historical ALU-only subset); real C.J/C.JAL/C.JR/C.JALR/C.BEQZ/C.BNEZ and C.LW/C.SW/C.LWSP/C.SWSP decoding; whole-image constant/window provenance and target/address proof; execution with the `pc+2` link; `generate_compressed_control_program`, `generate_compressed_memory_program`, policy-aware mutation. |
| `src/myfuzz/fuzz/f1_program_gate.py` | Four new flags and their mode names; `image_base` through validation and the expectation; `traced`/`compressed` properties; the expectation keeps the same `(pc, insn_word, rd, wdata)` projection and FNV-1a 32. |
| `src/myfuzz/fuzz/strategy.py` | New flags plus `f1_image_base`; fresh/mutated programs for the new shapes; `trace_deterministic`/`compressed_trace_deterministic` are must-known fixpoints over the real CFG, so only trace-deterministic programs are offered. |
| `scripts/run_inprocess_f1f6.py` | Emits `F1_ALLOW_JUMPS`/`F1_ALLOW_LOOPS`/`F1_ALLOW_COMPRESSED_CONTROL`/`F1_ALLOW_COMPRESSED_MEMORY`; passes the slot address as the image base; loop-aware trace correspondence (`prog_pc_repeat`); `prog_pc_repeat` observation key; strategy wiring; shape text in the summary/inputs document. |
| `scripts/inprocess_obi_apb_f1f4_spike.cpp` | New macros and `F1_TRACED`; policy-aware parcel admission; `f1_control` whole-image proof (jumps, canonical loop with its exact retirement count, compressed targets and memory addresses); `make_record` refusal and record facts; loop-aware retirement ordering and `prog_pc_repeat`; exact loop pass criterion; case-line print. |
| `configs/scenarios/inprocess-obi-apb-ibex-timer-{6w-jumps,6w-loops,4w-compressed-control,4w-compressed-memory}-{f1f6,fuzz}.json` | Eight new scenarios on the existing OBI Ibex + PULP timer + ZipDMA declaration. |
| `tests/fuzz/test_entry_f1_controlflow.py` | 41 new tests (flags, JAL/JALR, loop, compressed control/memory, strategy, correspondence, compiled C++ mirror). |
| `runs/round1-f1-controlflow/` | Real evidence: fixed and fuzz batches, case lines, trace hashes, independent verification, refusals, regressions. |

## Supported subset (and the refusals)

* **JAL/JALR** with link `x0`/`x1` and a statically proven, strictly forward
  target inside the image; `JALR` needs `rs1 = x0` or a register the program
  proves holds one exact constant.  The link writeback is `pc + 4`, exactly as
  RVFI reports it.
* **The canonical bounded loop**: `addi xN,x0,K` (K in 2..6), a body that never
  writes `xN`, `addi xN,xN,-1`, `bne xN,x0,head`; intervals disjoint, entered
  only at the init, static termination and an exact retirement count.
* **Compressed control**: C.J/C.JAL/C.BEQZ/C.BNEZ forward, C.JR/C.JALR with a
  proven constant base; backward compressed transfers refused.
* **Compressed memory**: C.LW/C.SW (base x8..x15) and C.LWSP/C.SWSP (base x2)
  with a proven in-window base and 4-byte aligned offset; reserved load
  destinations refused.
* **Refused by name** (and reported): backward JAL/JALR, `jal`-spelled loop back
  edges, compressed loops, non-canonical/nested/entered loops, trip counts
  outside 2..6, unproven or unaligned `JALR`/`C.JR` targets, unproven compressed
  memory bases, out-of-window compressed offsets, FP/stack/RV64 compressed
  forms, `C.JR x0`, and every impossible flag combination (jump/loop with
  compressed or address forms, loops without branches, compressed control/memory
  without the compressed declaration, new flags in single-word mode).

## Real evidence (summary; full case lines in the run README)

| Run | Cases | Result | Key evidence |
|---|---|---|---|
| `fixed-jumps` | 2 | observations_passed 2/2, correspondence matched | JAL: 3 retirements, `prog_trace_hash 0x20cee9b7`; JALR: 4, `0x1bb7b41c`; both `prog_rd_mask 0xa2` (x1 link writeback) |
| `fixed-loops` | 1 | observations_passed 1/1, matched | 13 retirements from 5 words, `0x030a0aaf`, `prog_pc_order 0`, `prog_pc_repeat 2` |
| `fixed-compressed-control` | 3 | observations_passed 3/3, matched | C.J 6 / `0x3ab734c9`; C.JAL 6 / `0x9fcee5a9`; C.JR 5 / `0xa87e4a06` |
| `fixed-compressed-memory` | 2 | observations_passed 2/2, matched | C.LW/C.SW 5 / `0x63793c59`, store witnessed (`data_changed 1`); C.LWSP/C.SWSP 5 / `0x09ee362a` |
| `fuzz-20-jumps` (seed 20261114) | 20 | 20 passed, 20/20 matched | 49 features, 10 corpus entries, 0.033 s host |
| `fuzz-20-loops` (seed 20261115) | 20 | 20 passed, 20/20 matched | every case `prog_pc_repeat` 1..5, count = `len+(K-1)*loop_length` |
| `fuzz-20-compressed-control` (seed 20261116) | 20 | 20 passed, 20/20 matched | forward C.J/C.JAL/C.BEQZ/C.BNEZ images |
| `fuzz-20-compressed-memory` (seed 20261117) | 20 | 20 passed, 20/20 matched | C.LW/C.SW and C.LWSP/C.SWSP images, store cases `data_changed 1` |

`runs/round1-f1-controlflow/verify_cases.py` re-derives every reference trace
from the saved case line's printed window: **88/88 saved cases matched**
(8 fixed: 2 JAL/JALR + 1 loop + 3 compressed control + 2 compressed memory, and 80 fuzz), `all_checks true`.

## Regressions

Nine batches re-run on the final tree: address forms (fixed 2/2, fuzz 20/20),
forward branches (fixed 1/1 with the identical `0xd2403c87`, fuzz 20/20),
compressed parcels (fixed 1/1 with the identical `0xe232c69e`, fuzz 20/20),
multi-IP 6/6, DMA len8 1/1, IRQ multilink 7/7.  Log:
`runs/round1-f1-controlflow/regressions/regressions.log`.

## Tests

`PYTHONPATH=src:. python3 -m pytest tests/fuzz
tests/integration/test_inprocess_f1f6_entry.py -q` -> **1166 passed** (the 41
new tests are `tests/fuzz/test_entry_f1_controlflow.py`; the 70 F1 gate tests and
the existing branch/compressed/address/subword suites are unchanged and green).
The new tests include a compiled C++ mirror of the `F1_CONTROL_FLOW` block that
agrees with Python on the exact records the real runs used and refuses the same
unproven forms.

## Changed-file inventory (git)

`git diff --stat` does **not** cover the F1 implementation files: this
repository tracks neither `scripts/run_inprocess_f1f6.py`,
`scripts/inprocess_obi_apb_f1f4_spike.cpp` nor `src/myfuzz/fuzz/*` (they appear
as untracked `??`), so the tree's own diff is not a record of this increment.
Instead:

* `runs/round1-f1-controlflow/host-snapshot.diff` (21 hunks, all F1: macro
  block, `Record`/`Observation` fields, policy-aware parcel block, the new
  `f1_control` namespace, `make_record` gate, retirement ordering,
  `prog_pc_repeat`, pass criterion, case-line print);
* `runs/round1-f1-controlflow/entry-snapshot.diff` (24 hunks; the F1 hunks are
  `prog_pc_repeat`, image-base plumbing, the four macros, the loop-aware
  classifier and trace correspondence, strategy flags, limit/feedback text; the
  remaining hunks in that file are concurrent edits by another agent on the
  shared entry and are not part of this increment);
* new files: the eight scenario configs, `tests/fuzz/test_entry_f1_controlflow.py`,
  `runs/round1-f1-controlflow/**`.

No `git reset`/`clean`/`checkout`/`stash` was used, and no existing run or doc
was deleted.

## Truth policy

Every claimed form has a saved real case line and trace hash; the trace hash is
the Python reference value, compared by the entry's correspondence and
re-derived independently by `verify_cases.py`.  A unit test is not an RTL pass,
and no coverage, certificate or replay claim is made.  Forms that could not be
made safe (backward jumps, compressed loops, `jal`-spelled loop back edges,
non-canonical loops, unproven indirect targets) are refused by name and listed
above.
