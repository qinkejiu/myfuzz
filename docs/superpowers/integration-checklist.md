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
| I4 | Reference-free Ibex + OpenTitan declaration | Pending |
| I5 | Generated-only RVX boundary | Pending |
| I6 | Isolated reference evaluation | Pending |
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
