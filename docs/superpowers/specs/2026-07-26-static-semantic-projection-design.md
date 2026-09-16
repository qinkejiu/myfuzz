# Static Semantic Projection Design

## Goal

Improve RFuzz coverage with a target-independent, static dependency-aware
projection while retaining baseline-like execution throughput and preventing
target-specific tuning.

## Scope

The training targets are the real Ibex + OpenTitan common-IP system and RVX
multicomponent system. The baseline remains direct raw-bit slicing. The
candidate uses only combinational transforms generated from declared port ABI,
protocol field IDs, address regions, legal value sets, and semantic roles.

The design does not use DUT internal hierarchy, coverage bits, source file
names, module names, instance names, target IDs, or hand-written register
sequences. Public DUT outputs may be declared in manifests for future protocol
work, but the static projection phase does not read them and has no sequential
state.

## Projection Model

```text
RTL port ABI + protocol plugin + semantic declarations
                    -> static policy portfolio
raw fuzz bits       -> combinational projection -> DUT public inputs
```

Every candidate preserves the baseline's raw-bit width, raw-bit geometry,
coverage universe, RFuzz mutation settings, seed, and time budget. It may only
apply these deterministic, combinational primitives:

- `mask/align` for declared address alignment and field widths;
- legal-set remapping for declared opcodes and enumerations;
- same-sample dependency gates for declared control relationships;
- one-hot or priority selection for declared mutually exclusive events;
- rarity folds for declared debug, reset, error, and interrupt events; and
- an entropy mix that retains declared direct-pass-through samples.

The portfolio varies only generic parameters: direct-pass-through ratio,
event rarity, legal-set mapping strength, and mutual-exclusion policy. It may
not vary target-specific constants.

## Screening And Promotion

Each candidate is first run for 60 seconds with one fixed seed. It is rejected
when it exits abnormally, loses more than 5 percent coverage, or reaches less
than 85 percent of baseline tests per second.

Survivors run 10 minutes on fixed seeds `1`, `7`, and `19` for both training
targets. A candidate is promoted only when all conditions hold:

- median covered-point improvement is at least 10 percent on both targets;
- no target/seed coverage result is more than 2 percent below its paired
  baseline result;
- median tests per second is at least 90 percent of paired baseline; and
- paired artifacts have equal coverage-universe identity, raw width, RFuzz
  settings, and budget.

Candidates are ordered by the lower of their two target improvements, then by
mean improvement, then by throughput. A promoted algorithm and its parameters
are frozen before long testing.

Frozen candidates run one hour on all three seeds for both training targets.
Reports retain raw coverage sets, overlap, candidate-only, baseline-only,
throughput, RSS, artifact hashes, and process return codes. No percentage is
compared across different coverage universes.

## Correctness Preconditions

Before screening, each target must prove that its program image begins at the
CPU reset entry, all declared event windows are reachable within RFuzz's
maximum test-cycle budget, and server/TOML/instrumentation artifacts agree on
input width and coverage identity. Early server or fuzzer exit, zero tests,
empty expected coverage, or leftover FIFO channels invalidate a run.

The current Ibex + OpenTitan target must repair and verify its reset-entry
image before any new coverage result is accepted.

## Held-Out Validation

After policy freeze, acquire two GitHub designs that did not participate in
tuning and represent different protocol families. Each source must have an
explicit open-source license, a pinned commit, and a build path compatible with
the existing Verilator/RFuzz stack. Add only ABI/protocol/semantic manifests;
do not change policy code or parameters for either held-out target.

Each held-out design receives the same 60-second and 10-minute process. A
failure is reported as a generalization result and does not trigger target
specific retuning.

## Test Strategy

Unit tests prove that policy generation is deterministic, depends only on
stable IDs and declared semantics, preserves raw ABI geometry, and is unchanged
when module or display names are renamed. Property tests cover output width,
legal-set membership, direct-pass-through availability, and absence of
sequential logic. Integration tests build real RFuzz servers and validate
artifact provenance, coverage-set collection, failure handling, and FIFO
cleanup.
