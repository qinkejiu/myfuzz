# myfuzz

myfuzz tests real CPU and IP RTL in separate harnesses. A total-control
environment selects a dataflow goal, then admits an upstream instruction or
external-event testcase. The intended long-running session starts CPU/IP
harnesses once and admits many testcases while RTL, RAM and pending events
persist. It routes real outputs according to declared dependencies, checks
properties and uses per-case feedback to guide later mutations. This
multi-testcase RFuzz lifecycle is implemented in fixed Ibex plus PULP GPIO and
OpenTitan UART pilots. General path contracts, broader search and the complete
acceptance gates remain in the implementation plan.

The active design does not build a concrete SoC RTL hierarchy or impose one
global cycle-accurate clock. Each CPU/IP keeps its native interface, protocol
and local timing; the scenario layer models cross-component data and causal
relations.

## Start here

| Need | Read |
|---|---|
| Run a first example | [Quick start](QUICKSTART.md) |
| Run F1–F6, live dependency search or coverage comparisons | [Universal runtime commands](docs/universal-runtime-usage.md) |
| Understand the system | [System overview](docs/SYSTEM_OVERVIEW.md) and [current design](docs/CURRENT_DESIGN.md) |
| Find code, configs and scripts | [Workspace map](docs/WORKSPACE_MAP.md) |
| Check current evidence and open gates | [Current progress](docs/CURRENT_PROGRESS.md) |
| Find a document or historical report | [Documentation index](docs/README.md) |
| Develop or verify a change | [Code organization](docs/CODE_ORGANIZATION.md), [scripts](scripts/README.md) and [tests](tests/README.md) |

The six-CPU/four-IP joint matrix and full P6/P7/P8 acceptance remain open.
Recorded software gates and fixed-instance RTL evidence have their own scopes;
see the current progress page before reusing a historical result.

## Current testcase execution

P1–P5 are complete within their declared scope ([P5 stage acceptance](docs/reports/current-dataflow-p5-stage-acceptance-20261008.md):
`p5_acceptance_suite.v1` critical items 6/6, exit 0; [P4](docs/reports/current-dataflow-p4-stage-acceptance-20261008.md):
8/8, exit 0).

**P6 and P7 advanced materially on 2026-10-14/15**, each with run artifacts kept
in the repository's evidence areas and each independently audited by a test that
recomputes the run's own numbers:

- **P7 A–E run end to end** from one command
  (`scripts/auto_harness_test.py`): D1–D4, a real RFuzz session and a fresh
  replay, `status=complete`, `exit 0`, **7/7 stages ok**, `matches: true`, on both
  shipped runtime families. Record:
  [P7-E end-to-end run](docs/reports/p7e-end-to-end-run-20261014.md).
- **P6 row 2 (full AXI4 / CVA6)** and **row 3 (AXI4-Lite / PicoRV32-AXI)** each
  ran a real **18-cell scenario campaign** to `gate_status: complete` (18/18 cells,
  no gate failures) over real RTL, with per-cell closed chains, feedback-driven
  mutation and full-prefix replay.
- **P6 row 4 (classic Wishbone)** is the row still open, with its remaining work
  named precisely rather than left vague.
- **CVW (CORE-V Wally) over AHB-Lite** reaches **session-level execution**: a
  generated harness boots the real core from the session's own memory service —
  the boot fetch is held, never zero-filled — and the core executes the program
  the session supplied. Its RFuzz *online* campaign is not yet wired.

P8 (real DMA) remains unaccepted. Historical UART FIFO/native IRQ gates have passed on
their recorded source snapshots. The v2
[controlled entry/read gate](docs/reports/current-dataflow-p2-controlled-entry-read-20261006.md)
recorded four taken, four entries and four retired UART reads, zero barriers,
and an equal complete fresh prefix of 48,315 events on its frozen source.
Runner changed afterward; that evidence does not revalidate the current source.
See [Current progress](docs/CURRENT_PROGRESS.md) for the latest result and
evidence identity. The runtime capability table describes recorded component
evidence, and the implementation plan defines the remaining gates.

Use `PYTHONPATH=src python3 -m myfuzz --help` for the shared harness/scenario
commands. `python -m myfuzz capabilities --match Ibex` lists documented evidence
and limitations with a source digest; it does not rerun RTL acceptance.

```text
Session: initialize selected independent CPU/IP harnesses once
  → choose F1–F6 dataflow goal, dependency path and unbound upstream source
  → admit one instruction or external-event testcase
  → CPU/IP RTL executes with component-local timing and persistent state
  → Router delivers real transactions, data and events to bound inputs
  → Scheduler admits later inputs after actual prerequisites occur
  → record per-case feedback; next testcase continues the same session
  → on finding, save and replay the complete session prefix
```

Fuzzer mutations apply to unbound source inputs, using the CPU ISA, local
protocol and component field rules. Bound inputs follow their upstream real
RTL outputs; persistent values change only through real writes or explicit
reset policy. A testcase may submit one RISC-V instruction and observe its
multi-cycle effects. A dataflow path may continue across later testcases.

## Code map

| Path | Role |
|---|---|
| `src/myfuzz/scenario/` | Genome, dependency graph, coordinator, dataflow router, scheduler, state, checkers, feedback and replay |
| `src/myfuzz/local_harness/` | Source-locked independent CPU/IP harness generation and local sessions |
| `src/myfuzz/integration/scenario_*` | RFuzz transport, scenario campaigns and replay integration |
| `src/myfuzz/protocols/` | Protocol templates, adapters, peers and monitors |
| `configs/cpus/`, `configs/peripherals/` | Verified component profiles and per-DUT tuning |
| `tests/` | Scenario contracts, harness generation and real RTL acceptance tests |
| `third_party/` | Pinned real RTL and dependencies used by builds/replay |
| `runs/scenario/acceptance/` | Saved evidence bundles and replay inputs; preserve as evidence |

## Extension rule

Adding a CPU or IP requires source/interface facts, an appropriate protocol
template, per-DUT declarative tuning where needed, a local harness acceptance,
and a testcase that proves real data/IRQ propagation and replay. Protocol name
alone is not sufficient to infer signal semantics. Start with
[`docs/CURRENT_DESIGN.md`](docs/CURRENT_DESIGN.md) and the capability matrix.

The repository retains earlier full-SoC composition and source-instrumentation
utilities for historical reproduction. Those paths are documented separately
and do not define the current independent-harness goal.
