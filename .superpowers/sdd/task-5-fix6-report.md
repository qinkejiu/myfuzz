# Task 5 Fix 6 Report

Baseline: `290bf66`. This change addresses the final independent Task 5
review. It changes only the generic composition planner, generic renderer,
their Task 5 tests, and this report. It does not stage or modify `third_party/`
or the pre-existing `.superpowers/sdd/task-2-report.md` edit.

## RED / GREEN

The reset regression puts a valid active-low reset module before a selected
`bad_cpu` module. The selected module uses `negedge rst` with `if (rst)`, which
must not be accepted. Before the fix, the planner accepted the plan because an
event offset relative to the selected module was used to slice the whole file.
The focused test failed with `ValueError not raised`.

Reset event matching and conditional inspection now both use the isolated,
masked target-module body. Ambiguous or unprovable reset behavior remains
fail-closed.

The filelist regression declares ordered `+incdir+zdir+adir` and
`+define+FILELIST_VALUE=1`. Before the fix, include roots were sorted and
macro definitions were omitted from both `sources.f` and Verilator lint. The
planner now records a normalized source-list context:

- Include roots retain first declaration order and de-duplicate by resolved
  path; repeated roots have no observable search effect.
- `+define+` options retain declaration order without de-duplication, because
  redefinition order is observable to an HDL frontend.
- `sources.f` and the Verilator invocation consume the same ordered roots and
  macro directives.
- Every traversed root filelist, including nested filelists, is included in
  `source_evidence_hash`; filelist-only mutations therefore invalidate the
  evidence hash.

All path resolution still rejects absolute, parent-traversal, escaping, or
symlinked source-list paths.

## Verification

RED:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest \
  tests.composition.test_generic_auto.GenericAutoCompositionTests.test_reset_contract_does_not_accept_evidence_from_an_unselected_module \
  tests.integration.test_generic_composition.GenericCompositionIntegrationTests.test_filelist_expansion_emits_hdl_and_filelist_include_roots -v
```

Result: two expected failures: reset proof was incorrectly accepted, and
include-root order was changed.

GREEN / Task 5 focused regression:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest \
  tests.composition.test_generic_auto \
  tests.integration.test_generic_composition \
  tests.composition.test_source_crawler \
  tests.composition.test_endpoint_capabilities -v
```

Result: `Ran 92 tests ... OK`.

Related legacy, protocol, RTL, and CPU-profile regression:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest \
  tests.composition.test_auto tests.composition.test_protocol_manifest \
  tests.composition.test_protocol_composer \
  tests.protocols.test_additional_protocol_catalog \
  tests.protocols.test_additional_protocol_rtl \
  tests.integration.test_cpu_profile_interfaces -v
```

Result: `Ran 54 tests ... OK`.

`PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m compileall -q src`
completed successfully, and `git diff --check` passed.

## Remaining risk

The reset recognizer intentionally supports only direct, simple clocked reset
conditionals. Macro-generated or delegated reset behavior remains rejected.
The source-list parser preserves supported `+incdir+`, `-I`, `-f`, `-F`, and
`+define+` semantics; unsupported filelist options remain fail-closed rather
than being silently omitted.
