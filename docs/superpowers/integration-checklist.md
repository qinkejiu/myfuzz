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
| I6 | Isolated reference evaluation | Published |
| I7 | Fair experiment matrix and report | Implemented; review pending |

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
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -W error::ResourceWarning -m unittest \
  tests.integration.test_reference_isolation \
  tests.experiments.test_configs tests.experiments.test_report -v
python3 scripts/check_identifier_policy.py --paths \
  src/myfuzz/composition src/myfuzz/harness src/myfuzz/integration --repo-root .
git diff --check
```

`ReferenceAdapter` is the sole production receiver for an evaluator command.
It pins the allowed root directory chain and validated executable inode across
handoff to the supervisor, so a root or intermediate path replacement cannot
alter what runs. Its stdout is discarded and stderr is continuously drained
with bounded diagnostic retention. The report admits a reference summary only
when its scope is `reference-descriptive`, and uses it only through the
stable-source intersection; candidate hashes and coverage universes remain
unchanged. Independent I6 review remains pending.

## I7 Gate

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest discover \
  -s tests/integration -p 'test_*.py' -v
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest discover \
  -s tests/experiments -p 'test_*.py' -v
python3 scripts/check_identifier_policy.py --paths \
  src/myfuzz/composition src/myfuzz/harness src/myfuzz/integration --repo-root .
git diff --check
```

`run_experiment_matrix` composes B's immutable `plan_experiment`, exact-token
`run_job`, and authoritative `build_report` boundaries. Build prerequisites run
before seeded fuzz interleaving; typed hard-memory events persist checkpoints
before bounded, B-priority retries. Only B-selected manifests and validated
per-job samples reach B's report builder, and the unchanged B report is wrapped
with execution metadata before atomic publication. Runner results bind the
current attempt and exact peak-RSS evidence. The report parent and any existing
destination inode are pinned before planning, while rollback keeps a durable
recovery backup until restoration is confirmed. Checkpoint sinks receive
detached events, and publication verifies the pinned destination inode across
an atomic name exchange. Independent I7 review remains pending.
