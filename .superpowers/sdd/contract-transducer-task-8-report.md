# Task 8 — Real Ibex from RFuzz-derived instructions

Worktree: `/home/qinkejiu/myfuzz/.worktrees/ibex-protocol-longrun`.
Implementation baseline: `e2ad088` (Task 7).

## Implementation

- Replaced `build_candidate`'s boot-memory component, boot-image construction,
  simulator boot-image argument, fixed first-fetch comparison, and peripheral-pass
  acceptance with the compiled contract transducer.
- The example declares `input_mode=contract_transducer`; instruction and data
  functions share `main`. Six external fields cover debug request, NMI, software,
  timer, external, and fast interrupts. The generated cycle record is 104 bits,
  transported as 16 bytes with 24 ignored trailing padding bits.
- Fixed header: `cycle_test.v1`, reset 2 cycles, execution limit 200, boot address
  128, hart 0, legal instruction mode. Transducer settings: 32-bit addresses/data,
  RV32IMC, M privilege, alignment 2, max wait 16, capacity 256, random errors disabled.
  Capacity and provenance errors remain active.
- Every newly generated instruction is selected/repaired from a cycle record;
  data reads and timing also consume the record. CPU-written bytes remain exact.
  No fixed instruction image is present in the candidate build.
- Added contract execution monitoring at the generated public backend boundary.
  Initializations count successful instruction reads of previously uninitialized
  aligned beats; successful data reads and nonempty writes occupy the same address
  set. Empty writes do not. Errors are target error responses plus protocol errors
  and outer backend errors without a corresponding target error (including watchdog).
  Propagated target errors are not counted twice. Bounded individual inputs may
  have zero requests or one unfinished tail request; probe and aggregate progress
  are checked separately. The legacy fixed-program monitor remains available.
- `compose`/`test` summaries now publish layout, constraint, transducer, header,
  composition identities and instruction source. `test` verifies progress, zero
  errors, shared-memory cleanup, replay count, and matching identities before pass.
- Added `replay --input ... --output <saved run> --build-output <new build>` to
  independently rebuild and verify retained corpus coverage and identities.
- Updated both Chinese documents and command sheet with the exact header, bit
  ranges, selector examples, handshake repair, shared-address behavior and commands.
  Replaced old expected figures solely with measurements from this task.

`compile_contract_transducer`'s actual interface is `external_inputs={field_id:
width}`, rather than the brief's illustrative `external_fields=...` argument.
The external map is derived from verified composition fields. The debug endpoint's
role is `request`, not a canonical fixed runtime control, so its old fixed default
was removed; it is now an explicit raw external field.

## Necessary scope extensions

The controller approved extending `rtl_execution_monitor.py` and its tests because
the old monitor required boot/pass facts and rejected every random program without
a fixed pass write. `rfuzz_simulator.py` now passes the monitor mode to parsing and
checks monitor capacity/shared-domain compatibility.

Real acceptance exposed ordinary upstream RTL diagnostic output mixed with the
simulator feedback stream. This required a generic framed-output fix in
`rfuzz_simulator.py`, bounded diagnostic retention in `rfuzz_live.py`, and regression
tests. No CPU RTL or third-party source was modified, and assertions were not disabled.

## TDD evidence

Commands below ran with `PYTHONPATH=src python3`.

1. Example/schema/proof RED:

   ```text
   -m pytest tests/examples/test_real_ibex_rfuzz_example.py
       tests/integration/test_ibex_protocol_campaign_smoke.py
       tests/integration/test_rtl_execution_monitor.py -q
   7 failed, 16 passed, 5 subtests passed in 8.26s
   config.get("input_mode"): None != "contract_transducer"
   contract monitor: execution monitor requires explicit boot/pass facts
   ```

   The initial real-build test used `/tmp`, outside the required publication root.
   After correcting that fixture path, before production implementation:

   ```text
   -m pytest tests/examples/test_real_ibex_rfuzz_example.py -q -k candidate --tb=short
   proof.get("instruction_source"): None != "rfuzz_contract_transducer"
   1 failed, 16 deselected in 14.58s
   ```

2. Additional schema/summary/replay RED:

   ```text
   -m pytest tests/examples/test_real_ibex_rfuzz_example.py -q
       -k 'invalid_contract or compose_publishes or bounded_acceptance or replay_command' --tb=short
   4 failed, 1 passed, 16 deselected, 4 subtests passed in 0.20s
   ```

   Failures were missing transducer identity, accepting mismatched replay count,
   accepting a negative boot address, and missing replay command. GREEN:
   `4 passed, 16 deselected, 5 subtests passed in 0.11s`.

3. Contract monitor RED/GREEN (delegated implementation, shared files reviewed):
   initial `3 failed, 2 passed, 5 subtests passed`; expanded RED included real
   Icarus boundary traces. GREEN covered configurations, orphan/duplicate events,
   instruction tags, shared-address initialization, data/empty/nonempty writes,
   reset, propagated errors, watchdog and Icarus/Verilator integration.

4. Real stdout-framing regression RED:

   ```text
   -m pytest tests/examples/test_real_ibex_rfuzz_example.py -q -k candidate --tb=short
   RtlSimulator.run_test -> _exchange: ValueError: oversized simulator response
   1 failed, 19 deselected in 17.16s
   ```

   The test feeds selector 174 and response choice 3 for 80 cycles. Selector 174
   produces legal CSRRW encoding `0x00001073`; unimplemented CSR 0 traps in Ibex.
   Direct execution of the retained model printed four `Illegal instruction`
   diagnostic lines followed by a valid feedback frame with metrics
   `80,13,13,13,13,6,0,0,0`. The old parser assumed all stdout was one frame.

   Generic real-pipe framing tests initially had `10 failed, 6 passed,
   7 subtests passed`. Added cases also first failed for stale diagnostics after
   rejected input and a diagnostic tail without newline. The fix recognizes only
   explicit protocol lines and retains ordinary stdout as `last_diagnostics`.
   Limits per exchange: 1024 lines, 256 KiB original bytes, 4096 bytes per line.
   Duplicate/truncated/stale protocol frames, output floods, fatal/EOF remain errors.
   Live reports count all captured lines and retain at most 32 samples.

   Real Ibex GREEN: `1 passed, 19 deselected in 17.03s`, including two identical
   feedback results for the CSR trap input. Generic simulator/monitor GREEN:
   `54 passed, 82 subtests passed in 31.06s`.
   Diagnostic-report helper RED was a missing callable; GREEN was
   `1 passed, 19 deselected in 0.11s` and verifies 80 lines with only 32 samples.

## Client diagnostics and actual commands

The planned `runs/rfuzz_client_native_build/release/rfuzz-client` does not exist.
Read-only `rg`, `file`, `ldd` and `--help` found the repository's native official
client `runs/rfuzz_client_native_build/target/debug/kfuzz`, version `kfuzz 0.1.0`.
All dynamic libraries resolved. The controller approved this local substitute.
No replacement client build, patch, download or third-party edit was needed.
Client SHA-256: `bbb72e52e60b1380cccd3b8c25febf0b6ccde51b17802d457ffadef43f87747b`.

```bash
PYTHONPATH=src python3 examples/real_ibex_rfuzz/run_example.py compose --input examples/real_ibex_rfuzz/input/ibex-scratch.json --output runs/examples/contract-rfuzz-compose
PYTHONPATH=src python3 examples/real_ibex_rfuzz/run_example.py test --input examples/real_ibex_rfuzz/input/ibex-scratch.json --client runs/rfuzz_client_native_build/target/debug/kfuzz --output runs/examples/contract-rfuzz-5s --seconds 5
PYTHONPATH=src python3 examples/real_ibex_rfuzz/run_example.py inspect --output runs/examples/contract-rfuzz-5s
PYTHONPATH=src python3 examples/real_ibex_rfuzz/run_example.py replay --input examples/real_ibex_rfuzz/input/ibex-scratch.json --output runs/examples/contract-rfuzz-5s --build-output runs/examples/contract-rfuzz-replay
```

All four final commands exited 0. The first test attempt failed after 14,823 RTL
tests, 2.938744 seconds with `unexpected simulator response framing`; its public
protocol/transducer errors were zero and all owned segments were cleaned. Its
complete directory was preserved as `runs/examples/contract-rfuzz-5s-framing-failure`
before rerunning the original command. No failed attempt was counted as a pass.

## Raw result summaries

Compose stdout:

```json
{"status":"passed","execution":{"cycles":80,"requests":2,"completions":2,"instruction_requests":2,"instruction_responses":2,"instruction_initializations":2,"protocol_errors":0,"transducer_errors":0,"errors":0}}
```

Successful test/inspect stdout (selected original fields):

```json
{"status":"passed","tests":124153,"completed_feedback_exchanges":98557,"corpus_entries":23,"replay_entries":23,"duration_seconds":29.523972176000825,"returncode":0,"remaining_segments":[],"execution":{"cycles":9932240,"requests":249246,"completions":248306,"instruction_requests":249246,"instruction_responses":248306,"instruction_initializations":248306,"protocol_errors":0,"transducer_errors":0,"errors":0}}
```

The saved live report records `requested_duration_seconds=5`,
`interrupt_elapsed_seconds=5.0000030219998735`,
`drain_seconds=24.52269833199898`, and peak sampled RSS `108146688` bytes.
The official client finishes its current batch after the stop request; therefore
this is a 5-second stop request with bounded drain, not a strict 5-second wallclock
cap. Four ordinary CSR trap diagnostic lines were retained. The successful run
required no forced shared-memory removal (`removed_owned_segments=[]`).

The saved corpus includes its seed and newly discovered coverage entries. Every
entry has a completed shared-memory receipt and verified real RTL feedback.
The feedback type is sampled DUT signal-bit events with saturating 8-bit counters,
not source branch coverage. The runtime observes 20 external input bits plus two
public backend signals.

Independent rebuild stdout: `status=passed`, `mode=replay`, `replay_entries=23`.
`rebuild_replay.json` confirms 23 original/rebuilt pairs match raw input,
layout, constraint, transducer, header, physical-control and simulator-input hashes;
every saved coverage vector was reproduced. Original binary hash:
`sha256:530550550a64985b063fdc7d48066369de3673b34b62bf097f09f7f6fdb8cda4`.
Rebuilt binary hash:
`sha256:059c78cc06a38e7e2193d83e98a8b97534b35471ed990832310a43e800e275c5`.
Binary hashes are recorded separately because rebuild output paths differ.

Matching build/live/replay identities:

| Identity | Value |
| --- | --- |
| composition | `sha256:04456100aa3e8af5b743cb6b842353e58953323e27f8343c1c34d650a33209b3` |
| layout | `sha256:d23dd16f9cd98973407167d90bd3431d82c7736bf2519eef8c47934fad111d8a` |
| constraint = transducer | `sha256:6fcbb39a28ca4e157b2fde393a305feb87d1a192a0b6c1d9b7de74d6782e6d38` |
| header | `sha256:e75c5138856cc7b92c781edf93b9bf88fd017d04b65aeb7b09eb1d72cfa4c881` |

## Regression and repository checks

Exact focused regression:

```bash
PYTHONPATH=src python3 -m pytest tests/composition/test_constraint_ir.py tests/composition/test_cycle_input.py tests/isa/test_instruction_transducer.py tests/composition/test_coherent_memory.py tests/composition/test_protocol_transducer.py tests/composition/test_contract_transducer.py tests/composition/test_transducer_rtl.py tests/integration/test_constrained_backend_rtl.py tests/examples/test_real_ibex_rfuzz_example.py -q
```

Result: `237 passed, 5 subtests passed in 46.55s`.

The requested bare `PYTHONPATH=src python3 -m pytest -q` exited 3 during collection:
it recursively imported third-party Ibex `google_riscv-dv/scripts/gen_csr_test.py`,
which calls `sys.exit` when its optional `bitstring` package is absent. No project
test failure was established by that collection error. The safe full-project
alternative is `PYTHONPATH=src python3 -m pytest tests -q`; it is also the command
now used by `commands.sh full-tests`. Final result:
`1399 passed, 3 skipped, 1132 subtests passed in 154.11s (0:02:34)`.
The three skips are the existing official-client/real-CPU opt-in tests; the
required real Ibex acceptance was executed separately above.

`bash -n examples/real_ibex_rfuzz/commands.sh` and `git diff --check` passed with
no diagnostics at the latest check.

## Scope, limitations and self-review

- This task proves the real Ibex split instruction/data path. Unified routes still
  fail closed. The candidate's 32-bit backend and example-specific schema are not
  a new acceptance result for CVA6, BOOM or other CPUs.
- The personality is composition metadata; constrained mode disables fixed targets.
  No scratch/GPIO/timer functional pass is claimed. The older
  `configs/campaigns/*-real-rfuzz.json` fixed-boot configurations have not been
  migrated and are rejected by the new candidate requirement. Their three-personality
  long campaign cannot be presented as three distinct peripheral executions here.
- Formal 3×300-second and BOOM acceptance remain false. Random bus error injection
  is disabled for this zero-error acceptance, but capacity/provenance enforcement
  remains enabled; arbitrary longer inputs can intentionally encounter those errors.
- The probe is 80 zero-valued RFuzz-format records; it is explicitly separate from
  the official client's live mutations. Repeated successful reads reuse memory;
  CPU writes are never silently repaired. Header controls remain fixed.
- The monitor observes generated public boundary wires only. No CPU-internal force,
  hierarchical state inspection, or CPU-name-specific branch was introduced.
- The stdout fix preserves diagnostics and strict protocol framing rather than
  suppressing upstream assertions or replacing trap behavior. Bounded retention and
  cleanup have dedicated failure-path tests.
- `rfuzz_simulator.py` was already a large integration module. Changes are confined
  to monitor binding and framed IO; no unrelated restructuring was undertaken.
- Existing `.superpowers/sdd/task-2-report.md` modifications and all third-party
  untracked material belong to the user. They were not edited or staged by this task.
  Only explicit Task 8 file paths will be staged.

Files changed: the six example/config/docs/result files; `real_cpu_campaign.py`,
`rtl_execution_monitor.py`, `rfuzz_simulator.py`, `rfuzz_live.py`; the example test
and three integration test modules; this report. The existing
`test_ibex_protocol_campaign_smoke.py` requires no source change and is included in
the project regression.
