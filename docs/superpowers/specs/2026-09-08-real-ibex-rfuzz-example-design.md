# Real Ibex RFuzz Example Design

Date: 2026-09-08

## Goal

Add a self-contained, Chinese-language example directory that explains the
current system capabilities and demonstrates the real Ibex path from
source-backed automatic composition through input-constraint projection and a
bounded official-RFuzz-client test.

The example must use the existing production implementation. It must not copy
or fork protocol matching, composition, constraint, simulator, feedback, or
corpus logic.

## Deliverable

Create this tracked directory:

```text
examples/real_ibex_rfuzz/
├── README.zh-CN.md
├── input/
│   └── ibex-scratch.json
├── run_example.py
├── commands.sh
└── expected/
    └── bounded-result.json
```

`README.zh-CN.md` is the primary handoff. It describes implemented capability,
the end-to-end data flow, prerequisites, artifact meanings, known limitations,
and commands that can be copied from the repository root.

`input/ibex-scratch.json` is a runnable real-Ibex input. It pins the interface
description, ISA contract, OBI protocol expectation, randomizable interrupt
fields, physical control defaults, boot memory, and scratch-register
personality.

`run_example.py` is a thin CLI over production APIs. It has three subcommands:

- `compose`: load and validate the input, automatically create the processor
  boundary and address map, project constraints, generate and compile the
  Verilator simulator, and run the existing deterministic real-CPU probe.
- `test`: perform the same fail-closed build, then run the official RFuzz client
  for a user-selected bounded duration, retain corpus and IPC evidence, and
  replay every retained input.
- `inspect`: print a concise summary from a completed example output without
  rebuilding or running external processes.

`commands.sh` contains commented, directly executable examples for dependency
checks, composition, the 5-second short test, result inspection, targeted unit
tests, and the separate formal three-by-300-second campaign command.

`expected/bounded-result.json` records the already observed five-second result
as reference evidence, not as output that a new run is required to reproduce
bit-for-bit.

## Data Flow

```text
source checkout + interface description + example input
  -> source and elaborated-port identity validation
  -> semantic processor-boundary discovery
  -> OBI adapter selection from protocol facts
  -> boot-memory and scratch-register allocation
  -> generated CPU/adapter/arbiter/backend/peripheral wiring
  -> ISA and field constraints projected into an RFuzz input layout
  -> Verilator compilation
  -> real Ibex boot and bounded execution probe
  -> official RFuzz shared-memory requests and RTL feedback
  -> interesting corpus retention
  -> replay and identity verification
```

The example may name Ibex because it is sample configuration data. Production
selection remains CPU-name-independent and must continue to dispatch from
interface, protocol, and capability facts.

## Input and Validation

The example input uses one peripheral rather than the three-personality
campaign list. The CLI converts it into the existing production configuration
shape before calling `build_candidate`.

Validation fails closed for missing or unknown keys, an unsupported schema
version, invalid duration, missing files, a nonexistent RFuzz client, or an
input personality that is not source-backed. Relative paths resolve against
the repository root so the same file works from any checkout location.

The input declares only interrupt fields as randomizable. Clock, reset, boot
address, hart ID, and other controls remain fixed. The generated runtime layout
and constraint hash are authoritative; the document must not imply that raw
fuzzer bytes directly drive unvalidated DUT ports.

## Commands and Outputs

The primary commands are:

```bash
PYTHONPATH=src:. JOBS=1 nice -n15 python3 \
  examples/real_ibex_rfuzz/run_example.py compose \
  --input examples/real_ibex_rfuzz/input/ibex-scratch.json \
  --output runs/examples/real-ibex-compose

PYTHONPATH=src:. JOBS=1 nice -n15 python3 \
  examples/real_ibex_rfuzz/run_example.py test \
  --input examples/real_ibex_rfuzz/input/ibex-scratch.json \
  --client runs/task14_client_cancel_build/debug/kfuzz \
  --output runs/examples/real-ibex-rfuzz-5s \
  --seconds 5
```

Output directories must not already exist, matching the production builder's
non-overwrite behavior. The commands publish machine-readable execution,
layout, live-run, corpus, replay, and summary evidence beneath their selected
output directories. Failures return a nonzero exit status and retain whatever
bounded diagnostic evidence the production layer publishes.

The README separately labels the formal acceptance command. It must not present
the 5-second example as satisfying the three sequential 300-second gate.

## Testing

Add unit tests for CLI input translation, duration and client validation,
summary inspection, and command help. Tests use mocks or existing lightweight
fixtures; ordinary regression must not build real Ibex or launch a long RFuzz
run.

Verification consists of the new focused tests, existing real-CPU/RFuzz
integration tests that do not require opt-in external execution, the full
Python regression, shell syntax checking for `commands.sh`, JSON parsing of all
example data, and `git diff --check`.

## Acceptance Boundaries

The example is complete when a new user can identify required dependencies,
understand the automatic decisions and constraint boundary, run separate
composition and short-test commands, inspect results, and locate the formal
long-run command.

The documented current result is the retained 5-second Ibex run: 15,357 RTL
tests, 13,440 completed feedback receipts, 19 corpus entries, successful first
fetch and execution progress, return code zero, and no remaining SysV shared
memory. BOOM and the three-by-300-second campaign remain explicitly unaccepted.
