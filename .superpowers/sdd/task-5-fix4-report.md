# Task 5 Fix 4 Report

Baseline: `506a48b`; the shared worktree also contains the separate Task 6
commit `edfb773`.  This fix changes and stages only Task 5 implementation,
Task 5 tests, and this report.  It does not modify or stage Task 6 files,
the pre-existing `.superpowers/sdd/task-2-report.md`, or `third_party/`.

## RED / GREEN

The new regressions were run against the pre-fix implementation.  They failed
because a `negedge` reset was accepted without polarity proof, omitted safety
capability declarations were defaulted permissively, a plugin gate of two
cycles still rendered a fixed 16-cycle adapter, an existing output directory
entered the backup/replace path, and a filelist was passed to lint as HDL
instead of preserving its expanded HDL/include context.

The generic planner now verifies reset contracts from explicitly annotated
clock/reset fields plus the matching HDL event control and reset conditional.
It records active-low/high and synchronous/asynchronous metadata only when the
two source-backed endpoints prove the same contract.  `negedge` without a
matching low-active conditional fails closed.  The renderer consumes that
metadata; it no longer hard-codes active-low asynchronous reset syntax.

The sole generic adapter now requires declared, safe values for one
outstanding transaction, no bursts, no IDs, single-beat operation, in-order
single-ID completion, ack/error completion, a finite legality gate, and a
finite `max_wait_cycles`.  Its IR and RTL timeout value is the minimum of the
projection temporal bound, any valid-to-ready temporal rule, and the declared
capability bound.  The regression proves a projection bound of two produces
`MAX_WAIT_CYCLES = 2` in both IR and generated RTL.

Publication uses a deliberately fail-closed safe transaction: any existing
output path (file or directory) is rejected before staging or mutation.  A
portable directory backup/replace/restore protocol cannot guarantee recovery
if the restore operation itself fails.  New tests monkeypatch `os.replace`,
`os.rename`, and `shutil.rmtree`, proving an existing output remains unchanged
and that an injected first-publication replace failure leaves neither output
nor hidden transaction directories.  First publication remains stage,
validate, then one `os.replace`.

Generic source collection filters expanded sources to HDL files, so a declared
`.f` file is never emitted as an HDL source line.  It recursively preserves
safe `+incdir+`/`-I` roots declared in filelists and emits them in the same
output-relative format as selected expanded HDL files.  Unsafe traversal,
absolute paths, symlinks, and missing include roots fail closed.

## Verification

RED (before implementation):

```text
5 targeted regressions: 4 assertion failures plus the filelist lint error
showing `sources.f` was treated as Verilog input.
```

GREEN:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest \
  tests.composition.test_generic_auto tests.integration.test_generic_composition -v
```

Result: `Ran 44 tests ... OK`.

The requested generic/source/contract/input-layout and legacy composition
suite was also run:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest \
  tests.composition.test_generic_auto tests.integration.test_generic_composition \
  tests.composition.test_endpoint_capabilities tests.composition.test_source_crawler \
  tests.composition.test_input_layout tests.composition.test_auto \
  tests.composition.test_protocol_manifest tests.composition.test_protocol_composer \
  tests.composition.test_cli -v
```

Result: 143 of 144 tests passed.  The only failure is the pre-existing
environment-dependent `test_builtin_ibex_plan_is_incomplete_when_upstream_is_absent`:
the protected, untracked `third_party/` tree supplies the upstream source list,
so the planner correctly reports a complete plan.  No `third_party/` content
was touched.
