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

- [Workspace inventory and cleanup record](docs/WORKSPACE_INVENTORY.md): what
each top-level directory is, what the 2026-10-09 cleanup removed and
regenerated, and the declared broken-link consequence.
- [System overview](docs/SYSTEM_OVERVIEW.md): how the current system is layered,
  how one online run proceeds, how it is verified, and what it does not claim.
- [Testcase and dataflow](docs/TESTCASE_AND_DATAFLOW.md): what one testcase is,
  how data flows inside it, which components it touches (two worked examples
  with real event ids).
- [Component reference](docs/COMPONENT_REFERENCE.md): every component and what
  it does, grouped by layer (340 modules).
- [Measured throughput](docs/THROUGHPUT.md): cases/s in three
  measures, the per-phase breakup, the 24x gap against the same-config
  2026-10-06 run, and what to fix.
- [How clock constraints are obtained](docs/CLOCK_CONSTRAINTS.md): profile
  declarations → request tick counts → plan-time validation/compilation →
  rendered clock toggling → host edge-count cross-check.
- [Four questions, answered with evidence](docs/FOUR_QUESTIONS_EVIDENCE.md): the
  peripheral-event declaration story, where the code volume comes from, the
  measured throughput bottleneck and how to raise it, and how timing is handled.
- [Testcase runbook](docs/TESTCASE_RUNBOOK.md): organised per testcase — the data
  flow, the components involved and how one test actually runs (command counts,
  per-case timing, replay path).
- [Testcase types](docs/TESTCASE_TYPES.md): the kinds of testcase and their
  dataflows (T1–T8, with real distributions, closure evidence and limits).
- [Input mutation basis](docs/INPUT_MUTATION_BASIS.md): what the mutation is
  grounded in — raw layout, the six declarative constraint gates, the 37
  rejection codes and the feedback weight formula.
- [Current progress](docs/CURRENT_PROGRESS.md): the single status entry for
  P0–P8, recorded gates and remaining acceptance work. **P1–P5 are accepted
  within their declared scope; P6–P8 are not.**
- [Current design](docs/CURRENT_DESIGN.md): input ownership, testcase flows,
  persistent state, router/scheduler responsibilities and remaining gaps.
- [Quick start](QUICKSTART.md): record/replay a real Ibex plus two-GPIO
  scenario and generate a local IP harness.
- [Reproduce the first step](docs/reproduction/first-step-p1-p5-20261008.md):
  P1–P5 stage gates, current read-only rechecks, saved outputs and limits.
- [First-step code and document audit](docs/reproduction/first-step-code-doc-audit-20261008.md):
  active modules, shared and historical paths, and issues found in review.
- [Runtime capability and evidence](docs/LOCAL_HARNESS_RUNTIME.md): verified
  CPUs, IPs, protocol profiles and exact limits.
- [Documentation index](docs/README.md): current design and historical
  evidence.
- [Implementation plan](docs/superpowers/plans/2026-10-06-current-dataflow-fuzz-implementation-plan.md):
  ordered gaps, code targets and acceptance gates.
- [Code organization](docs/CODE_ORGANIZATION.md): current execution chain,
  shared helpers and historical paths.
- [Repository cleanup audit](docs/reports/current-design-cleanup-source-audit-20261006.md):
  which files were moved and why shared/legacy code remains.

## Current testcase execution

P1–P5 are complete within their declared scope ([P5 stage acceptance](docs/reports/current-dataflow-p5-stage-acceptance-20261008.md):
`p5_acceptance_suite.v1` critical items 6/6, exit 0; [P4](docs/reports/current-dataflow-p4-stage-acceptance-20261008.md):
8/8, exit 0). P6 (multi-protocol reuse), P7 (automatic onboarding) and P8 (real
DMA) remain unaccepted. Historical UART FIFO/native IRQ gates have passed on
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
