# Harness-Specific Build Prerequisites Design

## Context

The static projection campaign compares `candidate-direct` and
`candidate-static` harnesses for the same target, seed, mutation settings, and
budget. These harnesses compile different RTL, so they cannot truthfully share
one server build merely because they belong to the same candidate design.

The current experiment planner deduplicates server builds by the candidate
build-cache key. A later fuzz job identifies its harness, but has no explicit
reference to the server build that implements that harness. Extending the
campaign runner around this ambiguity would make artifact provenance and
paired fairness unverifiable.

## Decision

Server build prerequisites are harness-specific. The existing experiment
planner remains the owner of build planning, and the existing experiment
matrix remains the owner of build-before-fuzz execution. No campaign-local
scheduler, lease manager, parser, or report aggregator is introduced.

Each build job identifies:

- the candidate design and its existing source/build-cache identity;
- the harness group and execution mode;
- the generated harness artifact identity, including the static source hash
  and projection-plan hash when the mode is `candidate-static`; and
- a stable build prerequisite ID derived from those identities.

Each fuzz job carries the exact build prerequisite ID it consumes. Planning
fails when that reference is missing, points to a build for another candidate
or harness, or disagrees with the fuzz job's declared artifact hashes.

## Planning Model

The planner treats `candidate-static` as a first-class candidate harness. It is
not an alias for `candidate-depaware`, and it does not inherit dependency-aware
runtime behavior.

Build deduplication uses the effective server identity rather than only the
candidate identity. Conceptually, the key is:

```text
(candidate build identity, harness mode, harness artifact identity)
```

Two fuzz jobs may reuse one build only when this complete key is equal. Jobs
with different seeds or budgets normally reuse a build; direct and static jobs
do not. If two static policies produce different generated source or projection
plans, they also do not reuse a build.

The build prerequisite ID is stable for equal normalized inputs and contains
no output path, process ID, timestamp, or display-only name. The planner emits
build jobs in deterministic order and emits each required build exactly once.

## Execution Contract

`run_experiment_matrix` executes the planned build jobs before their dependent
fuzz jobs, using its current scheduling and result collection path. Before a
fuzz job is dispatched, the matrix verifies that its referenced build:

- completed successfully;
- produced the expected server artifact;
- matches the candidate, harness mode, and artifact identities recorded by the
  fuzz job; and
- has not been substituted by a build with the same filesystem location but a
  different identity.

The runner receives the selected build prerequisite through the existing job
boundary. It materializes or selects that build's server for the fuzz job; it
does not rebuild the server during the fuzz stage.

Build failure invalidates all dependent fuzz jobs. A missing, duplicate, or
ambiguous prerequisite is a planning/execution error, not a skipped comparison.

## Static Harness Boundary

The public harness and design-flow interfaces accept `candidate-static`.
Static generation consumes only the normalized manifest semantics and the
globally selected portfolio policy. The generated bundle supplies declarations,
global parameters, source content hash, ABI hash, and projection-plan hash to
the planner.

Target configuration may declare ABI, protocol bindings, address regions,
legal sets, semantic roles, and artifact paths. It may not override policy
parameters. Both training targets use the same portfolio and selected global
policy.

## Fairness And Reporting

Training comparisons are explicit pairs between `candidate-direct` and one
named candidate harness, initially `candidate-static`. Pair validation retains
the existing equality requirements for coverage identity, raw width, mutation
settings, seed, and budget. It additionally requires each side's build
prerequisite and artifact hashes to be internally consistent.

Reports label the candidate harness dynamically instead of assuming
`candidate-depaware`. Static comparisons record the projection-plan hash and
the static-only coverage point IDs alongside the existing overlap and
candidate-only/baseline-only evidence.

No comparison is accepted when either prerequisite failed, the expected
coverage universe is empty, the run exits early or abnormally, zero tests were
executed, artifact hashes disagree, or FIFO cleanup is incomplete.

## Compatibility

Existing flat-direct, candidate-direct, and candidate-depaware experiments keep
their behavior. Existing callers that do not provide an explicit prerequisite
may be normalized by the planner only when exactly one compatible build can be
derived without ambiguity. Serialized job data gains a schema-compatible
optional field during loading, but newly planned fuzz jobs always contain an
explicit prerequisite ID.

This compatibility path must fail closed if more than one server build could
satisfy a legacy fuzz job.

## Verification

Focused tests must prove:

- direct and static fuzz jobs reference distinct builds;
- equal seeds/budgets reuse the correct harness-specific build;
- different static source or projection-plan hashes force distinct builds;
- missing, cross-harness, failed, and hash-inconsistent prerequisites fail;
- planner output and prerequisite IDs are deterministic;
- legacy single-build cases remain valid and ambiguous legacy cases fail;
- `candidate-static` flows through the public harness and design-flow APIs;
- reports compare direct against a dynamic candidate label and retain static
  provenance; and
- the campaign continues to use `run_experiment_matrix` for every stage.

The existing full unit suite and real sequential server build/handshake smoke
remain required before the campaign is considered integrated.
