# Task 5 Fix 3 Report

Baseline: `aead82a` (with the separate Task 6 commit `25dd948` already at
HEAD).  This commit stages only Task 5 implementation, tests, and this report.
It does not modify or stage `.superpowers/sdd/task-2-report.md` or the
untracked `third_party/` tree.

## RED / GREEN

New regressions were added and run before their fixes.  They demonstrated that
the generic writer previously accepted a forged IR after its self-declared hash
was updated, ignored component HDL and include-root byte changes, published
over an existing ordinary file (then attempted `rmtree` on the backup), and
accepted a synthetic multi-channel protocol or unknown reset semantics.

The writer now rebuilds the generic plan from the original request, catalogs,
source annotations, source pins, target bindings, topology, regions, IRQ
routes, dependencies, layout and canonical IR.  It compares the entire
reconstructed renderer input and renders only the rebuilt plan.  Selected CPU
and component files plus every declared include-root byte are pinned in a
source-evidence hash.  An existing non-directory output is rejected before
staging or destination mutation, preserving its bytes and type.

The only generic adapter form is now explicitly proven: both source and target
must have HDL evidence for the same clock and asynchronous active-low reset.
Other reset polarity/synchrony forms fail closed.  The adapter additionally
requires exactly one declared request/response channel relation, bounded
single-outstanding capability limits, and a declared bounded legality gate;
AXI-style or synthetic multi-channel declarations are rejected.  Built-in
profiles such as `timer` still lack real generic protocol/control target pins,
so they deliberately remain rejected rather than being rendered as complete.

`sources.f` records `cwd=output_dir` semantics in IR and uses only
output-directory-relative paths: include roots (`+incdir+`), selected sources,
and `generic_composition_top.sv`.  Sibling output directories therefore retain
byte-identical lists while every listed resolved path remains beneath
`base_dir`.

## Verification

Passed:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest \
  tests.composition.test_generic_auto tests.integration.test_generic_composition -v

PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest \
  tests.composition.test_endpoint_capabilities tests.composition.test_source_crawler \
  tests.composition.test_input_layout -v

git diff --check
```

The requested generic/legacy composition command was also run.  It executed
65 tests; 64 passed.  Its one expected environmental failure is
`test_builtin_ibex_plan_is_incomplete_when_upstream_is_absent`: the protected,
pre-existing untracked `third_party/` tree supplies the upstream path, so the
planner correctly produces a complete legacy plan.  No Task 5 file changes
caused that condition and no `third_party/` content was touched.
