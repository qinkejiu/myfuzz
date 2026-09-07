# Task 7 review correction

Scope: ISA catalog, CVA6/BOOM profiles and interface templates, their READMEs,
and `tests/integration/test_cpu_profile_interfaces.py`. No auto.py changes.

## Changes

- New-metadata profiles now load the real interface schema, compare every
  typed locator field, and invoke the source crawler with the protocol catalog.
  Source pin/content checks and required field/protocol checks must succeed
  before effective `implemented` becomes true. Missing/invalid dependencies
  yield `implemented=false` and no runtime protocols. Metadata-free legacy
  profiles retain the prior availability rules.
- Both templates declare `sources.f`; removed unconsumed `source_anchor` keys.
- CVA6 now describes an explicitly exported shared AXI4 boundary and all 29
  catalog fields. README explains flattening/export, aliases, dependencies,
  pinning and the separate adapter capability checks still required.
- BOOM remains reference-only: README and availability tests explicitly cover
  the unsupported `tilelink@1` dependency, even with valid pinned synthetic RTL.
- Generic tests now vary module and port names. The full AXI4 template is
  checked with two renamed port sets, correct annotation, catalog availability,
  and rejection after a required protocol role is removed.

## Verification

TDD red: initial focused run reproduced five false-positive executable states
(empty interface, missing source root, zero pin, mismatched locator and missing
required field) and the missing filelist template entry.

Green command:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest \
  tests.integration.test_cpu_profile_interfaces \
  tests.composition.test_source_crawler \
  tests.composition.test_endpoint_capabilities \
  tests.isa.test_catalog -q
```

Result: 70 tests passed (11 Task 7 tests). Scoped `git diff --check` passed.

No upstream CPU execution or Chipyard download was performed. The synthetic
tests establish template/crawler integration, not complete CVA6/BOOM runtime
support. Legacy plan hashing in auto.py remains assigned to the other agent.
User-owned third_party and task-2-report.md were not edited or staged.
