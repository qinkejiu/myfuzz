# Generated Ibex + two PULP GPIO: end-to-end acceptance

Date: 2026-10-05. The timed campaign ran with repository revision
`902100f42a0e599331761ad8e89077867c7c9857`. Its full local evidence is
under `runs/scenario/acceptance/ibex-two-pulp-gpio-optimized-10min-20261005/`.
The raw evidence is 843 MiB and remains in the local ignored `runs/` tree.
The `summary.json` SHA-256 is
`5c0dba49c8aad5f7f26019bc0a8e1c4b4433434f4a59a7f0cd4923124fef40e1`;
the first case's `manifest.json` SHA-256 is
`6bbff87827113de2e1726453c7323dfa2ad047faae3219458ec91cdcf1621061`.

## What the system runs

Three separate, generated local harnesses execute the pinned Ibex OBI RTL and
two pinned PULP APB3 GPIO RTL instances. One `ScenarioRunner` holds a testcase
open for 210 scheduler steps, without a reset inside the testcase. The CPU
program configures GPIO B, enables GPIO A output, writes GPIO A PADOUT, then
the router binds A's **observed RTL** `gpio_out[7:0]` to B's `gpio_in[7:0]`.
B's **observed RTL** IRQ is delivered as a bounded pulse to Ibex. The actual
Ibex interrupt handler fetches at `0x1012c`, reads B PADIN and interrupt
status through native transactions, and writes both results to persistent RAM.
There is no RTL SoC bus, bridge, arbiter, PLIC, or global cycle-accurate timing.

The only mutable source in the timed campaign is seven high bits of the CPU
program's GPIO output immediate. Bit 0 stays set to create a legal rising
edge, so the legal input space is the 128 odd bytes from 1 to 255. Bound GPIO
input, CPU IRQ, MMIO read data, and persistent RAM results are never separately
randomized. The source-aware scheduler starts with boundary and pattern values,
then favors values without observed RAM-result coverage. This timed driver is
**not** RFuzz coverage-guided search; the RFuzz 8-byte mutation bridge has a
separate real-RTL integration test.

The checker requires accepted CPU configuration and PADOUT writes, bounded
local GPIO output settling, producer-linked A→B dataflow delivery, actual B
IRQ and CPU ISR fetch, transaction-identified PADIN response, and a later
same-testcase RAM store. It reports missing causal stages as `path_incomplete`
and concrete value contradictions as `dut_violations`. A testcase with a
missing prerequisite is not counted as an RTL defect.

## Measured 600-second run

Command:

```bash
PYTHONPATH=src:. python3 scripts/runs/run_generated_ibex_two_gpio_10min.py \
  --seconds 600 \
  --output runs/scenario/acceptance/ibex-two-pulp-gpio-optimized-10min-20261005
```

| Measure | Result |
|---|---:|
| Cold preparation | 42.538 s |
| Effective search, including evidence and sampled replay | 600.654 s |
| Total wall time | 643.193 s |
| Completed testcase records | 420 |
| Checker-confirmed complete chains | 420 |
| Distinct legal source values / available | 128 / 128 |
| Assertion findings and failure classes | 0 / 0 |
| Fresh replay attempted / matched | 26 / 26 |
| Mean record time, including evidence saving | 1.345 s |
| Median record time | 1.321 s |
| Mean testcase time, including sampled replay | 1.430 s |
| Local ticks per testcase | CPU 70, GPIO A 78, GPIO B 90 |

The run exited with code 0. Replay was required for the first complete chain,
every fifth new observed RAM value, and any failure; the other 394 cases saved
full evidence but were not immediately replayed. `summary.complete` in this
revision means scheduler completion; the independently computed checker-complete
count is also 420. No upstream RTL bug was found in this bounded input space.

Before the authenticated build-preparation cache, a five-case baseline took
216.679 s of search time, with mean record time 29.241 s; all five chains
completed and two fresh replays matched. The optimized run still creates new
CPU and GPIO RTL processes for each testcase. It reuses only authenticated
preparation work, rechecks pinned input bytes and toolchain identity, and
validates the cached executable. The measured mean record-time improvement
for this workload is about 21.7×, not a claim about RTL execution speed.

## Additional acceptance after the timed run

After the timed revision was frozen, the repository added stricter transaction
identity checks, clearer campaign counters, a generated Ibex/PULP RFuzz source
map, and an independent reverse path. A main-worktree run of the three
integration modules completed 5/5 tests in 110.107 s. The forward RFuzz test
mutated only the CPU instruction source from 1 to `0x49` using two 8-byte
records, observed propagation through both real GPIOs, recorded its applied
source ID, and matched a fresh replay. The reverse path mutated B's external
input byte to `0x49`, `0x81`, and `0xff`; real B IRQ caused Ibex to read B and
write A, whose real `gpio_out` matched the chosen byte. CPU IRQ and MMIO read
data remained bound inputs. Eighteen associated static checker, ownership,
source-map, and campaign-summary tests passed. A synthetic corrupted trace
produced a `dut_violation` corpus entry, proving the reporting path; it is
not evidence of an actual RTL defect.

## Limits and next measurement

The timed search covers one fixed Ibex program shape and only the forward
CPU→GPIO A→GPIO B→CPU path. The reverse direction has real-RTL acceptance but
has not yet received a timed campaign. The seed scheduler uses semantic
dataflow novelty, not RFuzz feedback or a demonstrated time-to-bug comparison.
After all 128 legal forward values were seen, the remaining timed cases
measured stability and replay reproducibility rather than new source values.

The 42.538 s cold preparation is compilation and source admission. A future
long-lived RTL process pool could avoid process startup per testcase, but it
must explicitly reset all three DUTs and clear memory, pending events,
router/scheduler state, and event epochs between independent cases. That cost
and the size of the possible gain need profiling; preserving state across case
boundaries would change the replay and isolation contract.
