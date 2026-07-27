# Task 5A Implementation Report

## Status

Complete.

Commit: `a1d27fd` (`fix: publish concrete RFuzz matrix runner`)

## Summary

- Published canonical `sha256:` manifest hashes while preserving bare internal ABI and policy digests.
- Added instrumentation-to-coverage-universe conversion, RFuzz bitmap/statistics measurement, bounded atomic result publication, process-group cleanup, descendant RSS monitoring, and hard-memory termination to the existing design-flow driver.
- Extended `RfuzzAdapter` with a repository-relative `--result-json` boundary.
- Added `RfuzzExperimentRunner`, including strict result schemas, stale/missing/oversized result rejection, typed build/fuzz/resource mapping, atomic resource checkpoints, and measured coverage-manifest preparation.
- Wired the static-projection campaign CLI to the concrete runner and preparer, with exact smoke/training selection and a 7 GB hard-memory limit.
- Added focused unit/integration coverage, including a real temporary Python subprocess fixture rather than a mocked runner command.

## TDD Record

All commands ran from `/home/qinkejiu/myfuzz/.worktrees/integration` with `PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:.`.

### Canonical manifest hashes

RED:

```text
python3 -m unittest tests.experiments.test_pipeline.CandidateRuntimePipelineTest.test_frozen_runtime_fixture_produces_actual_three_mode_job_identities -v
```

Relevant output:

```text
ValueError: candidate_manifest.v1:harnesses:flat-direct:content_hash:invalid-hash
FAILED (errors=1)
```

GREEN: the same command.

```text
Ran 1 test
OK
```

The wider harness run then exposed three old assertions that still expected bare public hashes. After updating only those expectations, the focused fallout check was:

```text
python3 -m unittest tests.harness.test_harness.HarnessTest.test_candidate_static_is_a_first_class_task3_artifact tests.harness.test_compiler.HarnessCompilerTest.test_compiles_static_projection_with_direct_identity tests.harness.test_flow_integration.FlowIntegrationTest.test_stage_harness_materializes_all_modes_and_propagates_abi -v
```

```text
Ran 3 tests
OK
```

### Instrumentation coverage and RFuzz measurements

RED:

```text
python3 -m unittest tests.integration.test_rfuzz_runner.InstrumentationCoverageTest -v
```

Relevant output before implementation:

```text
AttributeError: module 'myfuzz.scripts.run_design_flow' has no attribute 'coverage_universe_from_instrumentation'
AttributeError: module 'myfuzz.scripts.run_design_flow' has no attribute 'covered_point_ids_from_bitmap'
```

After adding measurement and path cases, RED also reported absent `rfuzz_measurements` and `result_json_path`; the first implementation run identified and corrected a missing `math` import.

GREEN:

```text
python3 -m unittest tests.integration.test_rfuzz_runner.InstrumentationCoverageTest -v
```

```text
Ran 4 tests
OK
```

### Adapter result-document path

RED:

```text
python3 -m unittest tests.experiments.test_rfuzz_adapter.RfuzzAdapterTest.test_result_document_path_is_forwarded_to_the_existing_driver -v
```

Relevant output:

```text
TypeError: RfuzzAdapter.command() got an unexpected keyword argument 'result_json'
```

GREEN: the same command.

```text
Ran 1 test
OK
```

### Concrete runner and strict result mapping

RED:

```text
python3 -m unittest tests.integration.test_rfuzz_runner.RfuzzExperimentRunnerTest -v
```

Relevant output before implementation:

```text
ImportError: cannot import name 'RfuzzExperimentRunner' from 'myfuzz.integration'
```

GREEN after the subprocess-backed build/fuzz/rejection cases were implemented:

```text
python3 -m unittest tests.integration.test_rfuzz_runner.RfuzzExperimentRunnerTest -v
```

```text
Ran 3 tests
OK
```

### Campaign preparation, smoke mode, hard limit, and CLI wiring

RED preparation/smoke command:

```text
python3 -m unittest tests.test_static_projection_campaign.StaticProjectionCampaignTest.test_campaign_prepares_measured_coverage_before_every_matrix_plan tests.test_static_projection_campaign.StaticProjectionCampaignTest.test_smoke_runs_first_policy_for_both_targets_at_one_second_seed_one -v
```

Relevant output:

```text
TypeError: run_campaign() got an unexpected keyword argument 'preparer'
```

GREEN: the same command.

```text
Ran 2 tests
OK
```

RED hard-limit command:

```text
python3 -m unittest tests.test_static_projection_campaign.StaticProjectionCampaignTest.test_derived_config_is_atomic_repo_relative_and_parseable_by_existing_flow -v
```

Relevant output:

```text
KeyError: 'hard_memory_bytes'
```

GREEN: the same command.

```text
Ran 1 test
OK
```

RED CLI command:

```text
python3 -m unittest tests.test_static_projection_campaign.StaticProjectionCampaignTest.test_cli_constructs_concrete_runner_and_preparer_for_smoke -v
```

Relevant output after correcting the test fixture itself:

```text
SystemExit: no concrete RFuzz ExperimentRunner is published
```

GREEN: the same command.

```text
Ran 1 test
OK
```

## Final Verification

Focused command:

```text
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest tests.experiments.test_pipeline tests.experiments.test_rfuzz_adapter tests.integration.test_rfuzz_runner tests.test_static_projection_campaign -v
```

```text
Ran 33 tests in 0.765s
OK
```

Full repository command, run once:

```text
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest discover -v
```

```text
Ran 607 tests in 6.646s
OK
```

Additional checks:

```text
git diff --check
git diff --cached --check
```

Both exited 0 with no output.

## Files Changed

- `scripts/runs/run_static_projection_campaign.py`
- `src/myfuzz/experiments/rfuzz_adapter.py`
- `src/myfuzz/harness/direct.py`
- `src/myfuzz/integration/__init__.py`
- `src/myfuzz/integration/rfuzz_runner.py` (new)
- `src/myfuzz/scripts/run_design_flow.py`
- `tests/experiments/test_pipeline.py`
- `tests/experiments/test_rfuzz_adapter.py`
- `tests/harness/test_compiler.py` (canonical-hash expectation fallout)
- `tests/harness/test_flow_integration.py` (canonical-hash expectation fallout)
- `tests/harness/test_harness.py` (canonical-hash expectation fallout)
- `tests/integration/test_rfuzz_runner.py` (new)
- `tests/test_static_projection_campaign.py`

Commit total: 13 files, 994 insertions, 29 deletions.

The pre-existing unrelated modified/untracked paths named in the brief were not staged or committed.

## Self-Review

- Result documents are closed-world validated and bound to the current job/attempt before typed results are constructed.
- Result and checkpoint writes use temporary files, file fsync, atomic replacement, and parent-directory fsync.
- Repository-relative path boundaries reject absolute paths, `.`/`..` components, and resolved escapes.
- Fuzz server/fuzzer processes start in independent process groups; cleanup targets those groups, and RSS accounts for complete descendant trees discovered through `/proc`.
- Public manifest hashes are canonicalized only at the manifest boundary; internal plan/ABI identities remain unchanged.
- Campaign preparation occurs before matrix planning, so every matrix receives measured instrumentation coverage metadata.
- The final staged-file audit excluded all unrelated dirty paths.

## Concerns

- No live external RFuzz build/campaign was executed in this environment. The concrete boundary was verified with the real driver command construction, repository tests, and a temporary subprocess fixture that publishes actual result files.

## Review Fix Wave

The independent specification and quality reviews at `a1d27fd` both required
fixes. The follow-up implementation preserves flat-scope identity, requires
measured preparation, publishes matrix-owned per-seed pair evidence, gates
promotion on screening, binds fuzz evidence to both job and artifact, rejects
missing/stale/malformed statistics, verifies both FIFO types, retains observed
return/crash evidence, forwards the matrix hard-memory limit, and monitors and
cleans complete build/fuzz process groups.

Representative RED command:

```text
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest tests.integration.test_rfuzz_runner -v
```

The new lifecycle tests initially failed with three errors: missing
`load_rfuzz_measurements`, missing `rfuzz_fifos_ready`, and missing
`crash_restart_count` evidence. After implementation, the same focused runner
suite passed all 14 tests. The expanded adapter/runner suite then passed 37/37.

Final review-fix verification:

```text
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest \
  tests.experiments.test_pipeline tests.experiments.test_rfuzz_adapter \
  tests.experiments.test_static_portfolio \
  tests.integration.test_experiment_matrix \
  tests.integration.test_rfuzz_runner \
  tests.test_static_projection_campaign -v
```

```text
Ran 116 tests in 4.225s
OK
```

```text
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest discover -v
```

```text
Ran 636 tests in 9.491s
OK
```

`git diff --check` also exited zero. Live RFuzz evidence remains the next gate;
no coverage improvement is claimed from these unit/integration results.
