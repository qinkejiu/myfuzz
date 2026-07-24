# Integration Execution Checklist

This checklist records evidence for the `integration/dependency-aware-fuzz`
branch. A node is complete only after its focused test, diff check, push, and
remote ancestry check succeed.

| Node | Scope | Status |
| --- | --- | --- |
| I0 | Frozen cross-lane contracts | Published |
| I1 | Detached manifest join | Published |
| I2 | Identifier opacity and reference isolation | Published |
| I3 | Process-shared memory tokens and synthetic pipeline | Verified |
| I4 | Reference-free Ibex + OpenTitan declaration | Published |
| I5 | Generated-only RVX boundary | Published |
| I6 | Isolated reference evaluation | Implemented; review pending |
| I7 | Fair experiment matrix and report | Pending |

## I3 Gate

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest \
  tests.integration.test_memory_lock tests.integration.test_pipeline \
  tests.integration.test_manifest_join -v
python3 scripts/check_identifier_policy.py --paths \
  src/myfuzz/composition src/myfuzz/harness src/myfuzz/integration --repo-root .
git diff --check
```

The synthetic pipeline passes only immutable, typed declarations to injected
composition and runtime adapters. Reference/evaluator fields are rejected at
any configuration depth. Each producer invocation is covered by a shared,
exclusive memory lease. The default gate resolves through Git's common
directory, so distinct outputs and worktrees share one build lock. State
transitions are atomically persisted and retain bounded status and peak-RSS
history; every merged manifest is validated and serialized before publication.

## I5 Gate

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest \
  tests.integration.test_rvx_generation_boundary -v
python3 scripts/check_identifier_policy.py --paths \
  src/myfuzz/composition src/myfuzz/harness src/myfuzz/integration --repo-root .
git diff --check
```

The RVX generated-target declaration has one portable CPU/IP source root and
only typed source, component, port, protocol, and generic constraint inputs.
The candidate pipeline rejects reference/evaluator fields at any depth before
producer or output side effects. Missing external RTL returns
`dependency_unavailable`; reference evaluator files never enter generation
requests or candidate cache keys.

## I6 Gate

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest \
  tests.integration.test_reference_isolation \
  tests.experiments.test_configs tests.experiments.test_report -v
python3 scripts/check_identifier_policy.py --paths \
  src/myfuzz/composition src/myfuzz/harness src/myfuzz/integration --repo-root .
git diff --check
```

`ReferenceAdapter` is the sole production receiver for an evaluator command.
It pins the validated allowlisted executable inode across handoff to the
supervisor, so a path replacement cannot alter what runs. The report admits a
reference summary only when its scope is `reference-descriptive`, and uses it
only through the stable-source intersection; candidate hashes and coverage
universes remain unchanged.
