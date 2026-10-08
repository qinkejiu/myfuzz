# myfuzz Quick Start

This guide follows the current independent CPU/IP harness path. The intended
long-running session selects a dataflow goal and accepts successive instruction
or external-event testcases while RTL and memory state persist. The CPU fetches
instructions through its local memory interface; real RTL outputs feed bound
downstream inputs. Components keep their own protocol and local timing.

Read [the current design](docs/CURRENT_DESIGN.md) and
[the verified runtime matrix](docs/LOCAL_HARNESS_RUNTIME.md) for scope and
limits before adding a CPU/IP profile. The [implementation plan](docs/superpowers/plans/2026-10-06-current-dataflow-fuzz-implementation-plan.md)
lists the next gates for automatic path binding, instruction-target testcase
generation and coverage-guided mutation.

For the accepted first-step P1–P5 evidence, use the
[reproduction runbook](docs/reproduction/first-step-p1-p5-20261008.md). It
separates current read-only checks from the original RTL runs and replay.

## Record a continuous multi-component testcase

The checked-in Ibex example configures two independent OpenTitan GPIO harnesses.
It executes the testcase program from the CPU memory image, routes GPIO A's
real output to GPIO B, delivers GPIO B's real IRQ to Ibex, and keeps scenario
state across the testcase.

This command records **one** multi-cycle testcase with several causal actions.
The fixed Ibex plus PULP GPIO/UART online pilots use separate case identities in
one persistent Runner; their commands and limitations are linked from the
[report index](docs/reports/README.md).

```bash
MYFUZZ_SCENARIO_REAL=1 PYTHONPATH=src:. python3 -m myfuzz scenario record \
  --genome configs/scenario/ibex_two_gpio_closed_two_rounds.json \
  --factory myfuzz.scenario.examples:make_ibex_two_gpio_runner \
  --output runs/scenario/manual/ibex-two-gpio
```

The resulting evidence bundle contains the Genome, runtime manifest, immutable
run identity, trace, checker results and replay inputs.

## Replay from fresh harnesses

```bash
PYTHONPATH=src:. python3 -m myfuzz scenario replay \
  --evidence runs/scenario/manual/ibex-two-gpio \
  --factory myfuzz.scenario.examples:make_ibex_two_gpio_runner \
  --rebuild --compare-trace
```

Replay builds new harness sessions from the selected factory and compares the
recorded semantic trace. It validates repeatability of this configured
scenario; it does not establish support for arbitrary component combinations.

## Generate an independent local harness

Use a source-backed `local_harness.v2` request with the registered CPU/IP
profile, clock/reset facts, interface facts and any required declarative
tuning:

```bash
PYTHONPATH=src python3 -m myfuzz harness generate \
  --request configs/peripherals/opentitan_pattgen_local/request.json \
  --output runs/local-harness/opentitan-pattgen
```

The generator refuses a request whose source closure, interface facts or
protocol template cannot be verified. Same-protocol components may still need
profile-specific tuning. See [the harness extension design](docs/superpowers/specs/2026-10-04-generated-local-harness-five-protocol-design.md).

## Inspect the command options

```bash
PYTHONPATH=src python3 -m myfuzz capabilities --match Ibex
PYTHONPATH=src python3 -m myfuzz scenario record --help
PYTHONPATH=src python3 -m myfuzz scenario replay --help
PYTHONPATH=src python3 -m myfuzz scenario campaign --help
PYTHONPATH=src python3 -m myfuzz harness generate --help
```

The standalone scripts use the same parsers and handlers as these module
commands. Capability results preserve the runtime document's evidence and
limitations, with `runtime_revalidated=false`.

The old source-instrumentation and full-SoC composition flows remain in the
repository as separate historical utilities. Their commands and results are
not evidence that the independent-harness flow supports every CPU, IP or
protocol. The current evidence and known gaps are listed in
[`docs/LOCAL_HARNESS_RUNTIME.md`](docs/LOCAL_HARNESS_RUNTIME.md).
