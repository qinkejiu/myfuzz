# Task 5 Report: generic source-annotated composition

## RED

Added the Task 5 generic planner/integration tests before exposing the generic
API, then ran:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest tests.composition.test_generic_auto tests.integration.test_generic_composition -v
```

Result: expected failure. Both test modules failed to import
`GenericCompositionRequest` from `myfuzz.composition`, confirming the public
generic route did not yet exist.

## GREEN

Implemented and exported `GenericCompositionRequest`,
`GenericCompositionPlan`, `plan_generic_composition`, and
`write_generic_composition`. The planner now crawls/validates pinned sources,
normalizes endpoint capabilities, builds `InputLayout`, checks component
profiles, protocol preferences and capability fingerprints, records rejected
alternatives, validates dependency cycles/missing dependencies, allocates
aligned non-overlapping addresses, and allocates IRQs only from source-backed
IRQ input capacity. The generic renderer derives opaque top-level ports and
instance connections from annotation field facts, validates every source path
under `base_dir`, and stages all artifacts before publication.

The CLI now selects generic mode solely by the presence of
`--interface-description`; it requires `--base-dir` and retains the existing
protocol-manifest and candidate-search branches.

Focused verification:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest tests.composition.test_generic_auto tests.integration.test_generic_composition -v
```

Result: `Ran 6 tests ... OK`. This includes renamed synthetic CPUs, deterministic
IR/layout publication, missing annotations, capability/alignment/IRQ checks,
CLI mode, source-list/top output, and preservation of existing output after a
source disappears. The writer invokes Verilator lint when it is available;
this environment has it and the writer tests passed that boundary.

Legacy and generic regression excluding the externally invalidated absence
fixture:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 - <<'PY'
import unittest

suite = unittest.defaultTestLoader.loadTestsFromNames((
    "tests.composition.test_generic_auto",
    "tests.integration.test_generic_composition",
    "tests.composition.test_auto",
    "tests.composition.test_protocol_manifest",
    "tests.composition.test_protocol_composer",
))
def filtered(test):
    if isinstance(test, unittest.TestSuite):
        return unittest.TestSuite(filtered(item) for item in test)
    if test.id().endswith("test_builtin_ibex_plan_is_incomplete_when_upstream_is_absent"):
        return unittest.TestSuite()
    return test
result = unittest.TextTestRunner(verbosity=2).run(filtered(suite))
raise SystemExit(not result.wasSuccessful())
PY
```

Result: `Ran 34 tests ... OK`. This includes all remaining legacy auto,
protocol-manifest, and protocol-composer regression tests; their byte-output
assertions passed.

## Output contract

`write_generic_composition` publishes only after plan/source/serialization/top
validation succeeds, using a staging directory. It writes:

- `composition_ir.json` with path-independent source evidence IDs and selected
  component/match records.
- `input_layout.json`.
- `generic_composition_top.sv` with opaque stable port and instance IDs, while
  exact source port bindings come from HDL annotations.
- `sources.f` containing validated selected source files and the generated top.

The returned summary includes `interface_annotation_hash`,
`composition_ir_hash`, `layout_hash`, `top_path`, `source_list_path`, and
`complete` (plus schema version).

## Dependency-unavailable / environment condition

The exact requested combined command was run:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest tests.composition.test_generic_auto tests.integration.test_generic_composition tests.composition.test_auto tests.composition.test_protocol_manifest tests.composition.test_protocol_composer -v
```

It has one failure: `test_builtin_ibex_plan_is_incomplete_when_upstream_is_absent`.
The test assumes `third_party/rfuzz/upstream/ibex/sources.f` is absent, but the
shared worktree already contains that path under pre-existing untracked
`third_party/`; the planner therefore correctly reports a complete legacy Ibex
plan. This is an environment-condition conflict, not a Task 5 behavior change.
The directory was intentionally not modified, deleted, or staged.

## Final checks and scope

`git diff --check` completed successfully. No change was made to the protected
pre-existing `.superpowers/sdd/task-2-report.md`; it remains unstaged. The
generic additions avoid CPU-ID routing and do not use the legacy runtime
adapter/component-type/fixed-width tables. `protocol_manifest.py` was left
byte-for-byte unchanged because Task 5's generic path uses the source-backed
composition API and changing the legacy manifest would violate the compatibility
constraint.
