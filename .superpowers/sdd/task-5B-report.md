# Task 5B Implementation Report

## Status

Post-review implementation complete; bounded live smoke and coverage measurement
complete. The fixed 54-policy screen/promotion/validation campaign was not run in
this continuation, so no policy promotion or coverage-improvement claim is made.

## Summary

- Replaced the unavailable private `rfuzz_flow.tools` dependency with a repository-native integration over the vendored original RFuzz `top.cpp`, `fpga_queue.cpp`, `fpga_queue.hpp`, and `kfuzz` artifacts.
- Materialized a validated wrapper, DUT header, augmented TOML, and exactly one raw candidate ABI fragment per harness artifact.
- Bound coverage explicitly through `candidate.dut.__vi_coverage` and used the selected top's propagated coverage width as the logical universe.
- Accepted only exact logical or RFuzz-aligned bitmap widths, validated every byte, and ignored only the physical alignment tail.
- Kept Verilator server compilation at one worker under descendant RSS monitoring and the configured hard memory limit.
- Added `-Wno-fatal` after a real Ibex build proved that 1361 existing RTL/instrumentation warnings otherwise terminate elaboration; genuine Verilator errors remain fatal.

## TDD Record

All commands ran from `/home/qinkejiu/myfuzz/.worktrees/integration` with `PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:.`.

### Native original RFuzz boundary

Initial RED cases covered missing fixed original RFuzz files, absent native materialization, invalid candidate ports/inner instance, ambiguous ABI fragments, selected-top coverage binding, aligned bitmap width, and fixed single-worker construction.

GREEN focused suite:

```text
python3 -m unittest tests.test_original_rfuzz_native tests.experiments.test_rfuzz_adapter tests.harness.test_flow_integration tests.integration.test_rfuzz_runner -v

Ran 77 tests in 2.859s
OK
```

### Candidate source inclusion

The first real preflight exposed unresolved candidate hierarchy because the generated candidate source was not present in the Verilator command. The regression test first failed with:

```text
TypeError: build_server_command() got an unexpected keyword argument 'candidate_source'
```

After forwarding the validated raw ABI source, the focused case passed and the real build resolved `candidate.dut.__vi_coverage`.

### Existing warning policy

The second real preflight reached Verilator but failed with:

```text
%Error: Exiting due to 1361 warning(s)
```

The command test was extended first and failed because `-Wno-fatal` was absent. After adding the option, the same test passed and the same real preflight completed successfully.

## Real Preflight Evidence

Command:

```text
python3 src/myfuzz/scripts/run_design_flow.py --config runs/static_projection/smoke_20260727_1137/derived/ibex_opentitan_real_ip/policy-4b42539dd9898e9a/config.json --stage server --jobs 1 --candidate-mode candidate_direct --server-artifact-id sha256:344209b1754fd66658864bfb13e470cf385cbc435ba84aff77f98e4363dec76c --hard-memory-bytes 7000000000 --result-json runs/static_projection/preflight_task5b/ibex_candidate_direct_build.json
```

Observed result:

```text
artifact_id: sha256:344209b1754fd66658864bfb13e470cf385cbc435ba84aff77f98e4363dec76c
server_exists: true
server_size: 1089176 bytes
peak_rss_bytes: 493830144
resource_terminated: false
```

## Verification Note

One full 656-test run had a single timeout-sensitive failure in the unrelated reference FIFO isolation test immediately after the large Verilator build. Its isolated rerun passed in 0.181 seconds. A clean full-suite rerun then passed:

```text
python3 -m unittest discover -v

Ran 656 tests in 10.347s
OK
```

## Review-Fix TDD Record

The follow-up RED cases covered selected-module DUT scoping, strict selected-top
`__vi_coverage` width validation, materialized wrapper/header/TOML tamper
detection, non-object TOML coverage records, and the fixed `fuzzer.hpp` build
input. The initial focused run failed these cases as expected (82 tests: 6
failures and 1 error).

After the fixes, the focused suite passed:

```text
PYTHONPATH=src python3 -m unittest tests.test_original_rfuzz_native tests.experiments.test_rfuzz_adapter tests.integration.test_rfuzz_runner tests.harness.test_flow_integration

Ran 82 tests in 2.768s
OK
```

The complete suite also passed:

```text
PYTHONPATH=src python3 -m unittest discover -s tests -p 'test*.py'

Ran 661 tests in 9.584s
OK
```

The generated harness now records `sha256:` content hashes for the selected
candidate source, wrapper, DUT header, and augmented TOML; reload rejects any
bound artifact whose bytes no longer match its recorded hash. The selected
instrumented top source is passed into pre-build coverage validation when the
instrumentation record identifies a source file.

### Boundary parser follow-up RED

The follow-up boundary tests were run before the next production fix:

```text
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest tests.test_original_rfuzz_native -v

Ran 16 tests in 0.094s
FAILED (failures=4, errors=1)
```

The failures were the three non-ASCII identifier cases, a function-parameter
false positive for `__vi_coverage`, and non-ANSI selected-top source lookup.

### Scope and boundary hardening RED

The next RED command added string-literal, function/task-span, output-symlink,
and `sources.f` symlink cases:

```text
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest tests.test_original_rfuzz_native -v

Ran 18 tests in 0.098s
FAILED (failures=4, errors=2)
```

The failures were the string-literal scope case, function/task-only cases,
the mixed function plus real non-ANSI port case, the output symlink case, and
the symlinked source-list case.

The full suite was then rerun with permission to create the existing shared
memory-token lock under the integration worktree:

```text
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest discover -s tests -p 'test*.py'

Ran 667 tests in 9.191s
OK
```

## Post-review Remediation

Independent specification and code-quality reviews both returned
`DONE_WITH_CONCERNS`. Their Important findings were addressed before the live run:

- `RfuzzAdapter.availability()` and the native command boundary now require the
  fixed `fuzzer.hpp` input as well as `top.cpp`, `fpga_queue.cpp`,
  `fpga_queue.hpp`, and executable `kfuzz`.
- Candidate DUT discovery is scoped to the selected module body, emitted names
  use strict SystemVerilog identifiers, and the selected top's actual coverage
  output direction and width are checked before Verilator.
- Materialized wrapper, header, TOML, candidate source, source graph, and
  selected-top source are content-attested and revalidated on reload.
- Native build identity covers the source graph, fixed RFuzz C++/header inputs,
  extra sources and flags, Verilator binary/version/options, optimization, and
  the single-worker binding. Planner, build result, and fuzz artifact checks all
  carry that identity.
- Campaign-derived configs select the explicit upstream seeded fuzzer. Native
  infrastructure failures are classified separately from DUT crashes, and
  reproduce scripts bind the archived server/fuzzer/queue artifacts without
  destructive shell cleanup.

The review-fix RED command was run before these changes:

```text
PYTHONPATH=src:. python3 -m unittest \
  tests.test_original_rfuzz_native.OriginalRfuzzNativeTest.test_server_command_uses_original_inputs_and_one_build_worker \
  tests.integration.test_rfuzz_runner.InstrumentationCoverageTest.test_write_json_rejects_existing_symlink_destination \
  tests.integration.test_rfuzz_runner.InstrumentationCoverageTest.test_max_runs_is_a_valid_fuzz_budget \
  tests.integration.test_rfuzz_runner.InstrumentationCoverageTest.test_queue_entry_sort_key_uses_numeric_entry_id \
  tests.integration.test_rfuzz_runner.InstrumentationCoverageTest.test_reproduce_script_uses_artifact_server_and_supported_input_directory \
  tests.experiments.test_planner.ExperimentPlannerTest.test_native_rfuzz_input_identity_is_part_of_artifact_identity \
  tests.experiments.test_rfuzz_adapter.RfuzzAdapterTest.test_planned_commands_forward_native_rfuzz_input_identity

Ran 7 tests
FAILED (failures=2, errors=5)
```

After the fixes the same seven cases passed, followed by the cross-module and
complete verification runs:

```text
PYTHONPATH=src:. python3 -m unittest \
  tests.integration.test_rfuzz_runner tests.test_original_rfuzz_native \
  tests.harness.test_flow_integration tests.test_static_projection_campaign \
  tests.experiments.test_rfuzz_adapter tests.experiments.test_planner

Ran 156 tests in 8.687s
OK

PYTHONPATH=src:. python3 -m unittest discover -s tests -p 'test*.py'

Ran 686 tests in 15.103s
OK
```

`python3 -m py_compile` passed for all changed production Python modules,
`git diff --check` produced no output, and `git diff --name-only --diff-filter=U`
found no unresolved merge paths.

## Post-fix Live Evidence

The bounded campaign smoke was run only after the review gate:

```text
PYTHONPATH=src:. python3 scripts/runs/run_static_projection_campaign.py \
  --stage smoke \
  --config configs/experiments/static_projection_training.json \
  --out runs/static_projection/task5b_postfix_smoke_20260804
```

It exited `0`. Both targets built the three planned harness artifacts with
original RFuzz native sources and then completed one seeded one-second fuzz job
per artifact. All six fuzz results had `server_returncode=0`,
`fuzzer_returncode=0`, `handshake_succeeded=true`,
`fifo_cleanup_succeeded=true`, and zero DUT/resource failures. The measured
logical universes were Ibex `1853` points and RVX `324` points; direct/static
reports used matching per-target universes. The six build result documents
attested the same per-target native identities and Verilator version
`Verilator 5.020 2024-01-01 rev UNKNOWN.REV`.

The continuous measurement path was also exercised against the existing direct
and dependency-aware servers:

```text
PYTHONPATH=src:. python3 scripts/runs/run_sequential_coverage_pilot.py \
  --seconds 60 --sample-interval 20 --campaign-seed 1 \
  --label task5b_postfix_coverage_60s
```

It exited `0` with four jobs returning `server_returncode=0` and
`fuzzer_returncode=0`. Final observed queue unions were Ibex
`477/3713` (baseline) and `463/3713` (dependency-aware), and RVX
`145/324` for both. These are measurements from generated queue `trace_bits`
and are recorded under
`runs/pilots/task5b_postfix_coverage_60s_20260804_233735/`; they are not a
promotion result or a claim of improvement.

## Remaining Concern

The configured training campaign contains 54 policies and two targets. Its
screen stage is 108 one-seed jobs at 60 seconds each (6480 seconds of fuzzing
budget, about 1.8 hours before build overhead). If every policy passes screen,
promotion is 324 three-seed jobs at 600 seconds each (194400 seconds, exactly
54 hours before build overhead); validation adds 21600 seconds, about six
hours, for one selected policy. This continuation stopped after the bounded
post-review smoke and 60-second measurement; the full campaign remains a
separate long-running experiment and must be run in a dedicated window before
producing a frozen-policy decision.
