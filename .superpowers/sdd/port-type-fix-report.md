# Port type review fixes

Base: `a987b86`. Scope: `src/myfuzz/composition/source_crawler.py`,
`tests/composition/test_source_port_types.py`, and this requested report.

## Changes

- Reject directionless typed/interface prefixes before they inherit a prior
  direction/width or disappear as presumed non-ANSI names. Bare inherited names
  and non-ANSI bare headers still preserve `input int a,b` as signed 32-bit ports.
- Reject nonempty suffixes after port identifiers (including unmatched `]`),
  and nonempty inherited prefixes (including `[]`, ranges, and qualifiers).
  Existing unpacked-port rejection remains intact.
- Skip leading package-import declarations before scanning the module header's
  terminating semicolon. Parenthesized record parameter declarations remain
  inside the header; unresolved output type `T` fails closed. Builtin-only ports
  retain exact module/name/direction/width/signedness/file/line/column facts with
  either one or multiple imports.
- No CPU-specific logic or elaboration of opaque types was added.

## TDD evidence

1. Added regressions before production edits. Ran:
   `PYTHONPATH=src python3 -m pytest -q tests/composition/test_source_port_types.py`
   Result: **18 failed, 11 passed, 23 subtests passed**. All 18 failures were
   expected missing `SourceCrawlError` assertions: 12 directionless type cases
   and 6 inherited-prefix/trailing-syntax cases.
2. Applied declaration validation, then reran the same command. Result:
   **2 failed, 11 passed, 39 subtests passed**. Both builtin import cases exposed
   the wrong body-parsing path, which included the header's closing `)` in the
   port declaration. The original opaque-`T` import repro already raised before
   changes, but through that incorrect body-parsing path; it is retained as a
   fail-closed regression, not claimed as an initial failing test.
3. Corrected import/header scanning and ran only the requested focused files:
   `PYTHONPATH=src python3 -m pytest -q tests/composition/test_source_port_types.py tests/composition/test_source_crawler.py`
   Result: **44 passed, 77 subtests passed** (exit 0).
4. `git diff --check` passed. Reviewed the owned-file diff against all three
   findings. No reviewer-agent tool was available; independent integration
   review remains with main.

The initial command using `python` could not run because this environment has
`python3`, not `python`; it is not counted as red-test evidence.

## Handoff

No full suite was run while AXI work was underway. AXI files, `third_party/`,
and the pre-existing dirty `.superpowers/sdd/task-2-report.md` were not edited
or staged by this task. Main owns integration.
