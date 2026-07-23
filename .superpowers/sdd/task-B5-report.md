# Task B5 Report: Explicit Manifest Flow Integration

## Scope

Implemented B5 on `feature/harness-runtime` after B4 review approval.

Changed:

- `src/myfuzz/scripts/frontend_manifest_to_rfuzz_toml.py`
- `src/myfuzz/scripts/run_design_flow.py`
- `tests/harness/test_flow_integration.py`

## Behavior

- Removed the clock, reset, and active-low reset identifier tables and all
  equivalent semantic name lookup.
- TOML input selection validates the candidate manifest through the B4 ABI,
  joins frontend ports to numeric manifest records via `emitted_name`, checks
  direction/width/top-module consistency, and uses explicit semantic role and
  fuzz disposition fields.
- Missing controls, invalid active-level/reset metadata, unbound ports, and
  mapping mismatches fail before TOML emission. Explicit combinational
  manifests remain valid and do not require controls.
- `run_design_flow.py` accepts `--manifest`/`--candidate-manifest` and
  `--candidate-mode` (`flat_direct`, `candidate_direct`, or
  `candidate_depaware`), forwarding the selected mode through TOML and harness
  stages. The optional rfuzz harness package is imported only by the harness
  stage, so manifest/CLI validation works without that checkout.

## Review Fix: Unconditional Candidate Join

`write_toml()` validates the complete frontend/candidate-manifest join before
opening the TOML output or selecting manual harness input. This covers both
port directions and widths, while generated manual TOML still emits the raw
`rfuzz_input_bits` ABI input.

## Review Fix 2: Selected Top Identity And Explicit Fuzz Disposition

- Candidate top validation now compares `candidate_manifest.top.module` with
  the actual frontend module selected by `find_top_module()`. Either the
  selected module's `name` or `origName` is accepted, so fallback cannot make
  a candidate for a different requested module pass validation.
- The TOML emitter and raw ABI builder no longer treat a missing fuzz field as
  enabled. An input or inout must explicitly declare `fuzzable`,
  `fuzz_disposition`, or `disposition`.

### TDD Evidence

RED, before production edits:

```text
$ PYTHONPATH=src python3 -m unittest \
    tests.harness.test_flow_integration.FlowIntegrationTest.test_toml_rejects_candidate_top_that_only_matches_missing_requested_top \
    tests.harness.test_flow_integration.FlowIntegrationTest.test_toml_rejects_input_without_explicit_fuzz_disposition
Ran 2 tests ... FAILED (failures=2)
- a candidate top matching only the absent requested name was accepted after
  frontend fallback selected a different top module
- an input missing fuzzable was silently emitted as fuzzable

$ PYTHONPATH=src python3 -m unittest \
    tests.harness.test_harness.HarnessTest.test_rejects_input_without_explicit_fuzz_disposition
Ran 1 test ... FAILED (failures=1)
- the raw ABI silently selected an input with no explicit fuzz disposition
```

GREEN, after production edits:

```text
$ PYTHONPATH=src python3 -m unittest \
    tests.harness.test_flow_integration.FlowIntegrationTest.test_toml_rejects_candidate_top_that_only_matches_missing_requested_top \
    tests.harness.test_flow_integration.FlowIntegrationTest.test_toml_rejects_input_without_explicit_fuzz_disposition \
    tests.harness.test_harness.HarnessTest.test_rejects_input_without_explicit_fuzz_disposition
Ran 3 tests ... OK

$ PYTHONPATH=src python3 -m unittest tests.harness.test_flow_integration
Ran 12 tests ... OK

$ PYTHONPATH=src python3 -m unittest discover -s tests/harness
Ran 18 tests ... OK

$ PYTHONPATH=src python3 -m unittest discover -s tests/dependency
Ran 14 tests ... OK

$ PYTHONPATH=src python3 -m unittest discover -s tests/protocols
Ran 4 tests ... OK

$ PYTHONPATH=src python3 -m compileall -q src tests
exit 0

$ git diff --check
exit 0
```
