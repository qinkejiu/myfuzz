# Task 5 Fix 5 Report

Baseline: `e140969`.  This change addresses only the final Task 5 review
findings.  It changes Task 5 implementation, focused tests, and this report;
it does not modify or stage `third_party/` or the pre-existing
`.superpowers/sdd/task-2-report.md` edit.

## RED / GREEN

Before the fix, a selected endpoint named `bad_cpu` could use an invalid
active-high conditional with a `negedge` reset while an unrelated module in
the same source file supplied a valid active-low conditional.  The planner
incorrectly accepted the unrelated evidence.  The new regression failed with
`ValueError not raised`.

Reset proof now requires the source-backed module recorded for the selected
endpoint (or the selected component profile module).  It masks comments and
strings, extracts exactly one matching module body from each port-evidence
file, and only scans that body.  Missing, duplicate, or ambiguous module
evidence fails closed with `reset-semantics`.

Before the fix, include roots expanded from filelists were absent from IR
provenance, and Verilator lint received only HDL paths.  A real
`` `include "defs.svh"`` input therefore could not be linted.  The planner
now computes one normalized, source-root-contained include-root tuple before
building the IR.  The IR IDs, generated `sources.f`, source-evidence hash,
and lint invocation all consume that same tuple.  The writer passes the
validated resolved directories as Verilator `-I` arguments while preserving
stage-then-validate-then-single-replace publication.

## Verification

RED:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest \
  tests.composition.test_generic_auto.GenericAutoCompositionTests.test_reset_contract_does_not_accept_evidence_from_an_unselected_module \
  tests.integration.test_generic_composition.GenericCompositionIntegrationTests.test_filelist_expansion_emits_hdl_and_filelist_include_roots -v
```

Result: two expected assertion failures: reset was accepted, and the IR
include-root provenance was empty.

GREEN / focused Task 5 regression:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest \
  tests.composition.test_generic_auto tests.integration.test_generic_composition -v
```

Result: `Ran 47 tests ... OK`, including real Verilator lint coverage for
both a locator-declared include root and a nested-filelist `+incdir+` root.

```bash
git diff --check
```

Result: passed.

## Remaining risk

The reset recognizer intentionally accepts only simple clocked `always` /
`always_ff` forms with a directly observable reset conditional.  More complex
generated, macro-dependent, or delegated reset logic is rejected rather than
inferred.  This is fail-closed by design.
