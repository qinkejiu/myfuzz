# Low-Resource Runtime Mode Design

## Status

Direction approved by the user: work from `main` in an isolated worktree and add an opt-in low-resource mode.

## Goal

Provide a conservative, explicit execution profile for the existing protocol/harness/experiment stack so that a developer can validate the end-to-end path while other processes are using the machine. The profile must reduce candidate count, seed count, simulation budget, queue sizes, and memory policy without changing the normal experiment defaults.

The first implementation target is a deterministic synthetic smoke command. It will exercise the existing composition-to-runtime join, declared protocol loading, three harness modes, dependency-aware metadata, memory-gated experiment orchestration, and report publication. It will not launch an external Verilator build or a long-running RFuzz campaign.

## Non-goals

- Do not add full AXI4, TileLink, or CHI protocol semantics in this phase.
- Do not change the default values in checked-in experiment configurations.
- Do not add implicit auto-detection that silently changes a normal experiment.
- Do not run external HDL compilation, parallel fuzz workers, or a long fuzz campaign as part of the smoke command.
- Do not claim that the smoke command proves RTL correctness or production-scale performance.

## Design

### 1. Immutable resource profile

Add `myfuzz.experiments.resource_policy` with a frozen `ResourceProfile` and one built-in `CONSERVATIVE_PROFILE`.

The conservative profile is:

| Resource | Conservative value |
| --- | ---: |
| candidate count | at most 1 |
| seeds | first sorted declared seed only |
| budget | the explicitly named `smoke` budget only |
| build concurrency | 1 |
| waveforms | disabled |
| replay queue | at most 32 |
| event ring | at most 512 |
| field groups per batch | at most 16 |
| soft memory policy | at most 512 MiB |
| hard memory policy | at most 768 MiB |
| token size | at most 64 MiB |

The profile is applied by `apply_resource_profile(config, profile=...)`, which:

1. Deep-copies the planner configuration and never mutates its input.
2. Caps candidate and seed selection while preserving deterministic sorted order.
3. Selects only the existing budget whose name is exactly `smoke`; it fails closed if that budget is absent instead of shortening an arbitrary scientific budget.
4. Applies the queue, waveform, and concurrency ceilings.
5. Keeps an already stricter memory setting. Otherwise it lowers `soft_memory_bytes`, `hard_memory_bytes`, and `token_bytes` to the profile ceilings while preserving `token <= soft < hard`.
6. Raises a focused `ResourceProfileError` for malformed settings or an unusable profile rather than returning a configuration that will fail later for an unrelated reason.

The function operates on the existing `experiment.v1` planner configuration. The wrapper consumed by `run_experiment_matrix` remains unchanged, so the resource mode is an adapter-layer choice and does not broaden the report contract.

### 2. Low-resource smoke runner

Add a small orchestration function under `myfuzz.integration` and a thin CLI at `scripts/run_low_resource_smoke.py`.

The runner will:

1. Load the bundled runtime fixtures for HDL facts, composition IR, and a validated candidate.
2. Apply `CONSERVATIVE_PROFILE` to the Ibex experiment planner configuration, with optional command-line overrides for the report path and profile memory ceilings.
3. Invoke the existing `run_candidate_pipeline` in dry-run mode with the actual `prepare_candidate_runtime` adapter. This loads the declared `ready-valid-mmio` plugin, compiles the flat-direct, candidate-direct, and candidate-depaware harness artifacts, and constructs the dependency graph without starting a simulator.
4. Pass the joined runtime manifest to `run_experiment_matrix` with one deterministic in-process runner. The runner returns one valid synthetic sample per fuzz job and one successful build result; it performs no subprocess creation.
5. Publish a normal `experiment_report.v1` report when a report path is supplied. Without a report path, it uses a temporary directory and returns the report in memory, so the command does not leave repository artifacts.
6. Use a temporary memory-gate directory for the self-contained smoke run and restore the caller's environment afterward. Real experiments continue to use the existing shared memory gate.

The command will print a compact summary containing the selected profile, number of build/fuzz jobs, effective memory policy, and report location. It will be safe to rerun because all default output is temporary.

### 3. Public exports and documentation

Export the profile and application function from `myfuzz.experiments`, and export the smoke entry point from `myfuzz.integration`. Add `docs/low-resource-running.md` with the command, resource guarantees, override behavior, and explicit limitations. The documentation will distinguish the synthetic smoke from a real RTL run.

## Error handling and safety

- The profile is opt-in; existing callers and configuration files receive no changed defaults.
- Configuration input is detached before modification, preventing accidental cross-test or cross-run state changes.
- Missing `smoke` budget, invalid memory ordering, and non-positive limits fail before any pipeline or gate activity starts.
- The smoke runner uses temporary output and no external child process. A caller-provided report path is the only persistent output.
- The existing atomic report publication and memory-gate lease/release paths remain the source of truth; this feature does not duplicate them.

## Testing strategy

Add focused tests before implementation:

- `tests/experiments/test_resource_policy.py`: verify immutability, deterministic candidate/seed/budget reduction, queue and memory ceilings, preservation of stricter input limits, and fail-closed validation.
- `tests/integration/test_low_resource_smoke.py`: run the smoke orchestration with the real fixture adapters and deterministic runner boundary; assert one build, three fuzz jobs, one seed, the smoke budget, disabled waveforms, bounded queues, successful protocol/harness/dependency metadata, and a valid published report.
- Run the existing protocol catalog and experiment-matrix tests as regression coverage.

Verification will remain targeted (`unittest` modules and the smoke command). No full Verilator build or long fuzz campaign will be started on this machine during this phase.

## Planned files

- `src/myfuzz/experiments/resource_policy.py`
- `src/myfuzz/integration/low_resource_smoke.py`
- `src/myfuzz/integration/__init__.py`
- `src/myfuzz/experiments/__init__.py`
- `scripts/run_low_resource_smoke.py`
- `tests/experiments/test_resource_policy.py`
- `tests/integration/test_low_resource_smoke.py`
- `docs/low-resource-running.md`
