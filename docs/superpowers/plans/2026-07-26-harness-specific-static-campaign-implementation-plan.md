# Harness-Specific Static Campaign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Integrate `candidate-static` into the RFuzz experiment pipeline with a distinct, auditable server build prerequisite for every harness artifact, then compose the two-target static projection training campaign.

**Architecture:** The planner derives a stable server identity for each `(candidate, harness mode, harness artifact)` tuple and stores the selected build job ID on every fuzz job. The experiment matrix validates and completes those prerequisites before fuzz dispatch; report and campaign code continue to consume the existing plan and matrix APIs.

**Tech Stack:** Python 3 dataclasses, canonical SHA-256 contracts, `unittest`, myfuzz harness compiler, experiment planner/report/matrix, RFuzz design-flow CLI, JSON configuration.

## Global Constraints

- `candidate-static` is first-class and never aliases `candidate-depaware`.
- Every newly planned fuzz job contains an explicit `build_job_id`.
- Build reuse requires equal candidate identity, harness mode, content hash, ABI hash, and projection-plan hash.
- Harness/TOML/server outputs are isolated by validated artifact ID; one build may not overwrite another harness's server.
- Direct/static pairs keep coverage identity, raw width, mutation, seed, and budget equal.
- Target declarations contain no target-specific policy parameters.
- Budgets are exactly 60, 600, and 3600 seconds; promotion and validation seeds are exactly `1`, `7`, and `19`.
- Every campaign stage calls `run_experiment_matrix`; no new scheduler, lease manager, parser, or report aggregator is allowed.
- Build concurrency is `1`, waveforms are disabled, and real build smoke is sequential under `scripts/memory_gate.py`.

---

### Task 1: Expose the Static Harness Through the Public Design Flow

**Files:**
- Modify: `src/myfuzz/harness/__init__.py`
- Modify: `src/myfuzz/scripts/run_design_flow.py`
- Test: `tests/harness/test_harness.py`
- Test: `tests/harness/test_flow_integration.py`
- Test: `tests/experiments/test_rfuzz_adapter.py`

**Interfaces:**
- Consumes: `compile_static_policy(...) -> StaticPolicyPlan` and `build_static_harness(...) -> HarnessArtifact` from Task 3.
- Produces: `build_harness(manifest, mode, *, static_declarations=None, static_parameters=None) -> HarnessArtifact`, CLI support for `candidate_static`, and artifact-isolated flow paths selected by `--server-artifact-id`.

- [ ] **Step 1: Run the focused tests and verify the red state**

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest tests.harness.test_harness tests.harness.test_flow_integration tests.experiments.test_rfuzz_adapter -v
```

Expected: the new static-mode tests fail because the public boundary rejects `candidate_static`.

- [ ] **Step 2: Implement the typed public harness mode**

In `src/myfuzz/harness/__init__.py`, import `Mapping` and `build_static_harness`, add the mode, and extend `build_harness`:

```python
def build_harness(
    manifest: object,
    mode: str,
    *,
    static_declarations: Mapping[str, object] | None = None,
    static_parameters: StaticPolicyParameters | None = None,
) -> HarnessArtifact:
    if mode not in _MODES:
        raise ValueError(f"unknown harness mode: {mode}")
    if mode == "candidate_static":
        if static_declarations is None or static_parameters is None:
            raise ValueError("candidate_static requires static declarations and parameters")
        plan = compile_static_policy(
            build_raw_abi(manifest), static_declarations, static_parameters
        )
        return build_static_harness(manifest, plan)
    if static_declarations is not None or static_parameters is not None:
        raise ValueError("static inputs require candidate_static mode")
    if mode == "candidate_depaware":
        return build_depaware(manifest)
    return build_direct(manifest, mode)
```

- [ ] **Step 3: Materialize typed static configuration in the design flow**

Add `candidate_static` to `HARNESS_MODES`. Add a helper used by `stage_toml` and `stage_harness`:

```python
def build_configured_harness(manifest: object, cfg: Mapping[str, object], mode: str) -> HarnessArtifact:
    if mode != "candidate_static":
        return build_harness(manifest, mode)
    static = cfg.get("static_projection")
    if not isinstance(static, Mapping):
        raise ValueError("candidate_static requires static_projection config")
    declarations = static.get("declarations")
    parameters = static.get("parameters")
    if not isinstance(declarations, Mapping) or not isinstance(parameters, Mapping):
        raise ValueError("static_projection requires declarations and parameters")
    typed = StaticPolicyParameters(
        parameters.get("direct_ratio"),
        parameters.get("event_rarity"),
        parameters.get("legal_set_strength"),
        parameters.get("mutual_exclusion"),
    )
    return build_harness(
        manifest,
        mode,
        static_declarations=declarations,
        static_parameters=typed,
    )
```

Replace both direct `build_harness(manifest, candidate_mode)` calls with this helper. Global parameters live only in the derived runtime config.

Add `--server-artifact-id` to the CLI. Accept only `sha256:` plus 64 lowercase hexadecimal digits. When present, derive an isolated root beneath the configured output directory using the 64-digit suffix:

```python
def artifact_flow_paths(paths: dict[str, Path], artifact_id: str | None) -> dict[str, Path]:
    if artifact_id is None:
        return paths
    if re.fullmatch(r"sha256:[0-9a-f]{64}", artifact_id) is None:
        raise ValueError("server artifact ID must be a canonical SHA-256 identity")
    root = paths["out_dir"] / "server_artifacts" / artifact_id.removeprefix("sha256:")
    selected = dict(paths)
    selected.update({
        "toml": root / "instrumented" / paths["toml"].name,
        "harness": root / "harness",
        "server": root / "server",
        "queue": root / "queue",
    })
    return selected
```

For an artifact-specific `server` stage, load the existing frontend/instrumentation/candidate manifests, regenerate TOML and harness for the selected candidate mode inside this root, and then invoke `stage_server`. For `fuzz`, select the same root and never regenerate or rebuild the server.

- [ ] **Step 4: Run tests and commit**

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest tests.harness.test_harness tests.harness.test_flow_integration tests.experiments.test_rfuzz_adapter -v
git diff --check
git add src/myfuzz/harness/__init__.py src/myfuzz/scripts/run_design_flow.py tests/harness/test_harness.py tests/harness/test_flow_integration.py tests/experiments/test_rfuzz_adapter.py
git commit -m "feat: expose static projection harness mode"
```

Expected: focused tests pass and the diff check is clean.

### Task 2: Plan Harness-Specific Builds and Bind Every Fuzz Job

**Files:**
- Modify: `src/myfuzz/experiments/planner.py`
- Modify: `src/myfuzz/experiments/__init__.py`
- Modify: `src/myfuzz/experiments/rfuzz_adapter.py`
- Test: `tests/experiments/test_planner.py`
- Test: `tests/experiments/test_rfuzz_adapter.py`

**Interfaces:**
- Consumes: manifest harness records with `content_hash`, `abi_hash`, and optional `projection_plan_hash`.
- Produces: `ExperimentBuildJob.harness`, `ExperimentBuildJob.artifact_id`, `ExperimentJob.build_job_id`, `RfuzzExecution.server_artifact_id`, and `resolve_build_prerequisite(plan, fuzz_job) -> ExperimentBuildJob`.

- [ ] **Step 1: Add failing identity and reuse tests**

Assert direct/static fuzz jobs reference distinct builds, while all seeds and budgets for one harness reuse one build:

```python
builds = {job.job_id: job for job in plan.build_jobs}
direct_ids = {job.build_job_id for job in plan.jobs if job.harness == "candidate-direct"}
static_ids = {job.build_job_id for job in plan.jobs if job.harness == "candidate-static"}
self.assertEqual(1, len(direct_ids))
self.assertEqual(1, len(static_ids))
self.assertTrue(direct_ids.isdisjoint(static_ids))
self.assertEqual({"candidate-direct"}, {builds[value].harness for value in direct_ids})
self.assertEqual({"candidate-static"}, {builds[value].harness for value in static_ids})
```

Change only the static content hash and then only the projection-plan hash; each change must alter `artifact_id` and build job ID.

- [ ] **Step 2: Run the planner tests and verify missing fields fail**

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest tests.experiments.test_planner -v
```

Expected: failure because current build jobs have no harness identity and fuzz jobs have no prerequisite.

- [ ] **Step 3: Extend immutable job contracts and canonical documents**

```python
@dataclass(frozen=True, slots=True)
class ExperimentBuildJob(Job):
    execution: RfuzzExecution
    target_id: str = ""
    candidate_id: str = ""
    harness: str = ""
    artifact_id: str = ""
    harness_content_hash: str | None = None
    harness_abi_hash: str | None = None
    projection_plan_hash: str | None = None

@dataclass(frozen=True, slots=True)
class ExperimentJob(Job):
    # Keep the existing required fields in their current order.
    build_job_id: str = ""
```

Add `server_artifact_id: str | None = None` to `RfuzzExecution`. Allow all supported modes on server-stage execution, including `candidate_static`, while continuing to reject server seeds and budgets. Require a canonical server artifact ID whenever a newly planned server or fuzz execution selects a harness-specific build. Include every new field in canonical job documents so `plan_hash` covers the graph.

- [ ] **Step 4: Generate one build per effective server identity**

For every selected candidate and declared harness, derive:

```python
artifact_document = {
    "target_id": config.target_id,
    "candidate_id": candidate.candidate_id,
    "candidate_hash": candidate.candidate_hash,
    "build_cache_key": candidate.build_cache_key,
    "harness": harness,
    "candidate_mode": modes[harness],
    "harness_content_hash": content,
    "harness_abi_hash": abi,
    "projection_plan_hash": projection,
}
artifact_id = content_hash(artifact_document)
```

Build job identity includes `artifact_id`; both server execution and every dependent fuzz execution include the same harness mode and `server_artifact_id`. Pass the resulting build job ID to `_make_job`. Reject duplicate candidate/harness records with conflicting artifact identities.

In `src/myfuzz/experiments/rfuzz_adapter.py`, append both selectors for build and fuzz commands:

```python
if execution.candidate_mode is not None:
    command.extend(("--candidate-mode", execution.candidate_mode))
if execution.server_artifact_id is not None:
    command.extend(("--server-artifact-id", execution.server_artifact_id))
```

Adapter tests must assert a direct fuzz job, static build job, and static fuzz job each carry the artifact ID belonging to their referenced build.

- [ ] **Step 5: Implement fail-closed prerequisite resolution**

```python
def resolve_build_prerequisite(
    plan: ExperimentPlan,
    fuzz_job: ExperimentJob,
) -> ExperimentBuildJob:
    if fuzz_job.build_job_id:
        matches = tuple(job for job in plan.build_jobs if job.job_id == fuzz_job.build_job_id)
    else:
        matches = tuple(
            job for job in plan.build_jobs
            if job.candidate_hash == fuzz_job.candidate_hash
            and job.build_cache_key == fuzz_job.build_cache_key
            and (not job.harness or job.harness == fuzz_job.harness)
        )
    if len(matches) != 1:
        raise ExperimentPlanError("fuzz build prerequisite must resolve exactly once")
    build = matches[0]
    if build.harness and build.harness != fuzz_job.harness:
        raise ExperimentPlanError("fuzz build prerequisite harness does not match")
    for field in ("harness_content_hash", "harness_abi_hash", "projection_plan_hash"):
        if getattr(build, field) != getattr(fuzz_job, field):
            raise ExperimentPlanError(f"fuzz build prerequisite {field} does not match")
    if build.artifact_id != fuzz_job.execution.server_artifact_id:
        raise ExperimentPlanError("fuzz execution server artifact ID does not match")
    return build
```

Call the helper for every new fuzz job before the plan is frozen. The empty-ID path exists only for a unique legacy build and fails when ambiguous.

- [ ] **Step 6: Run tests and commit**

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest tests.experiments.test_planner tests.experiments.test_rfuzz_adapter -v
git diff --check
git add src/myfuzz/experiments/planner.py src/myfuzz/experiments/__init__.py src/myfuzz/experiments/rfuzz_adapter.py tests/experiments/test_planner.py tests/experiments/test_rfuzz_adapter.py
git commit -m "feat: plan harness-specific server builds"
```

Expected: planner output and prerequisite IDs are deterministic; adapter commands select the build job's mode.

### Task 3: Enforce Completed Prerequisites in the Existing Matrix

**Files:**
- Modify: `src/myfuzz/integration/experiment_matrix.py`
- Test: `tests/integration/test_experiment_matrix.py`

**Interfaces:**
- Consumes: `resolve_build_prerequisite` and the existing injected runner boundary.
- Produces: `BuildJobResult.artifact_id`, verified build-before-dependent-fuzz enforcement, and unchanged retry, lease, and publication behavior.

- [ ] **Step 1: Add failing matrix ordering and rejection tests**

Add cases for missing ID, unknown ID, cross-harness ID, mismatched planned hash, mismatched returned `artifact_id`, and a prerequisite that never returns a successful `BuildJobResult`. Update successful build fixtures to return the job's planned identity:

```python
return BuildJobResult(job.job_id, attempt=1, artifact_id=job.artifact_id)
```

On success, record calls and assert:

```python
for fuzz_job in plan.jobs:
    self.assertLess(calls.index(fuzz_job.build_job_id), calls.index(fuzz_job.job_id))
    build = next(job for job in plan.build_jobs if job.job_id == fuzz_job.build_job_id)
    self.assertEqual(build.artifact_id, fuzz_job.execution.server_artifact_id)
```

- [ ] **Step 2: Run the matrix tests and verify the red state**

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest tests.integration.test_experiment_matrix -v
```

Expected: new rejection tests fail because the matrix currently executes all builds without resolving fuzz dependencies.

- [ ] **Step 3: Validate the graph before execution and completion before dispatch**

Extend the result contract so a successful runner attests to the exact artifact it materialized:

```python
@dataclass(frozen=True, slots=True)
class BuildJobResult:
    job_id: str
    attempt: int
    artifact_id: str = ""
```

In `_validated_result`, require `result.artifact_id == job.artifact_id` for new harness-specific builds. Accept an empty result identity only when `job.artifact_id` is also empty, preserving the unique legacy-build path. Prerequisite resolution must also require the build's `artifact_id` to equal the fuzz execution's `server_artifact_id`.

At the start of `_run_experiment_matrix`, resolve every fuzz prerequisite and translate `ExperimentPlanError` into `ExperimentMatrixError`:

```python
prerequisites = {
    job.job_id: resolve_build_prerequisite(plan, job)
    for job in plan.jobs
}
completed_builds: set[str] = set()
```

Add a build ID only after a `BuildJobResult` with the matching artifact identity is validated. Immediately before every initial or retried fuzz dispatch:

```python
required = prerequisites[job.job_id]
if required.job_id not in completed_builds:
    raise ExperimentMatrixError(
        f"fuzz build prerequisite did not complete: {required.job_id}"
    )
```

- [ ] **Step 4: Run tests and commit**

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest tests.integration.test_experiment_matrix tests.experiments.test_planner -v
git diff --check
git add src/myfuzz/integration/experiment_matrix.py tests/integration/test_experiment_matrix.py
git commit -m "feat: enforce fuzz build prerequisites"
```

Expected: prerequisite failures stop before fuzz execution and existing retry behavior remains green.

### Task 4: Make Fairness and Reports Candidate-Harness Aware

**Files:**
- Modify: `src/myfuzz/experiments/planner.py`
- Modify: `src/myfuzz/experiments/report.py`
- Test: `tests/experiments/test_planner.py`
- Test: `tests/experiments/test_report.py`

**Interfaces:**
- Consumes: configured coverage comparison `candidate-direct` versus `candidate-static` or `candidate-depaware`.
- Produces: dynamic `CandidatePairIdentity.candidate_harness`, candidate identity, attribution keys, and static provenance.

- [ ] **Step 1: Write failing static-pair report tests**

```python
attribution = report["candidates"]["candidate-a"]["budgets"]["long"]["coverage_attribution"]
self.assertEqual("candidate-static", attribution["candidate_harness"])
self.assertEqual([3], attribution["static_only_point_ids"])
self.assertEqual([1], attribution["direct_only_point_ids"])
self.assertEqual([2], attribution["overlap_point_ids"])
self.assertEqual(expected_plan_hash, attribution["projection_plan_hash"])
```

Keep a depaware fixture proving `depaware_only_point_ids` remains available.

- [ ] **Step 2: Run report tests and verify static is rejected**

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest tests.experiments.test_planner tests.experiments.test_report -v
```

Expected: failure because planner and report hard-code `candidate-depaware`.

- [ ] **Step 3: Carry the configured pair through planner fairness and ordering**

Store `comparison_pair: tuple[str, str]` in `_PlannerConfig`. Require left `candidate-direct`, require one supported right candidate harness, and replace `_CANDIDATE_GROUPS` assumptions in `_audit_fairness` and `_run_blocks` with:

```python
direct_harness, candidate_harness = config.comparison_pair
```

Add `candidate_harness` and `candidate` to the identity. Preserve a read-only `depaware` compatibility property for depaware plans, and include the dynamic fields in the canonical fairness document.

- [ ] **Step 4: Generalize report attribution**

Derive the candidate harness from plan fairness. For static reports emit:

```python
coverage_attribution = {
    "comparison_scope": "harness-attribution",
    "candidate_harness": candidate_harness,
    "coverage_universe": direct_universe,
    "common_total": direct_total,
    "direct_only_point_ids": sorted(direct - candidate),
    "static_only_point_ids": sorted(candidate - direct),
    "overlap_point_ids": sorted(direct & candidate),
    "projection_plan_hash": projection_plan_hash,
}
```

Fail if static jobs disagree on projection-plan hash. Use the dynamic label in runtime and reference comparison; preserve existing depaware output names for depaware plans.

- [ ] **Step 5: Run tests and commit**

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest tests.experiments.test_planner tests.experiments.test_report tests.experiments.test_static_portfolio -v
git diff --check
git add src/myfuzz/experiments/planner.py src/myfuzz/experiments/report.py tests/experiments/test_planner.py tests/experiments/test_report.py
git commit -m "feat: report configured candidate harness pairs"
```

Expected: legacy depaware and new static reports both pass.

### Task 5: Compose the Two-Target Training Campaign

**Files:**
- Create: `configs/experiments/static_projection_training.json`
- Create: `configs/designs/ibex_opentitan_real_ip/static_projection/config.json`
- Create: `configs/designs/rvx_multicomponent/static_projection/config.json`
- Create: `scripts/runs/run_static_projection_campaign.py`
- Test: `tests/test_static_projection_campaign.py`

**Interfaces:**
- Consumes: `PORTFOLIO`, portfolio selection/freezing APIs, static compiler, and `run_experiment_matrix`.
- Produces: `load_campaign`, `validate_training_pair`, and `run_campaign`.

- [ ] **Step 1: Run campaign tests and verify the missing module/config red state**

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest tests.test_static_projection_campaign -v
```

Expected: failure because the campaign module and configs do not exist.

- [ ] **Step 2: Define strict immutable campaign types and loader**

```python
@dataclass(frozen=True, slots=True)
class CampaignStage:
    seconds: int
    seeds: tuple[int, ...]

@dataclass(frozen=True, slots=True)
class CampaignTarget:
    target_id: str
    config_path: str
    candidate_manifest_path: str

@dataclass(frozen=True, slots=True)
class CampaignConfig:
    screen: CampaignStage
    promotion: CampaignStage
    validation: CampaignStage
    targets: tuple[CampaignTarget, ...]
```

`load_campaign` rejects unknown keys, unsafe paths, duplicate targets/seeds, non-exact budgets/seeds, and target declarations containing `static_projection.parameters` or `static_projection.policy`.

- [ ] **Step 3: Add campaign and target declarations**

Create `static_projection_training.json` with screen `{60,[1]}`, promotion `{600,[1,7,19]}`, validation `{3600,[1,7,19]}`, and both training targets. Each target file declares `"portfolio": "static_projection.PORTFOLIO"`, reuses existing target ABI/protocol/artifact paths, and contains no policy values.

- [ ] **Step 4: Implement strict pair validation**

```python
def validate_training_pair(value: object) -> None:
    pair = _strict_object(value, {"baseline", "candidate"}, "training pair")
    baseline = _validate_run(pair["baseline"], "baseline")
    candidate = _validate_run(pair["candidate"], "candidate")
    for field in ("coverage_identity", "raw_width", "mutation", "seed", "budget"):
        if baseline[field] != candidate[field]:
            raise ValueError(f"training pair {field} mismatch")
```

`_validate_run` requires return code `0`, positive tests, nonempty expected coverage, elapsed time at least the seconds budget, equal declared/observed artifact hashes, and no existing FIFO. Reject boolean integers, non-finite elapsed values, malformed hashes, and missing fields.

- [ ] **Step 5: Build matrix input from one global policy**

For each stage/target/policy, compile exact static RTL and inject only the selected global parameters into a derived runtime design config. Atomically write that config beneath the campaign output directory at a repository-relative path so `RfuzzExecution.design_config_path` can pass it to the existing CLI. Set planner harnesses to flat/direct/static and comparison right side to `candidate-static`. Populate the static manifest record from the real bundle:

```python
static_record = {
    "raw_width": bundle.raw_width,
    "content_hash": bundle.content_hash,
    "abi_hash": bundle.abi.abi_hash,
    "projection_plan_hash": bundle.policy_plan_hash,
}
```

Never derive source identity from policy ID alone.

The derived design config retains the target's shared frontend/instrumentation paths, sets the selected global `static_projection.parameters`, and relies on `--server-artifact-id` for separate harness/TOML/server paths. Campaign code must not copy or rename one server into another artifact directory.

- [ ] **Step 6: Compose stages only through `run_experiment_matrix`**

Screen, promote, freeze, and validate using distinct atomic matrix report paths. Positive execution calls the matrix three times. If no policy qualifies, publish a deterministic negative promotion result and do not call validation.

- [ ] **Step 7: Run synthetic integration tests**

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest tests.test_static_projection_campaign tests.integration.test_experiment_matrix tests.test_ibex_opentitan_real_ip_target tests.test_rvx_multicomponent_target -v
```

Expected: every positive campaign stage uses the existing matrix and all invalid evidence fails closed.

- [ ] **Step 8: Run real sequential build/handshake smoke**

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 scripts/memory_gate.py --claim build --memory-mib 3072 --owner static-campaign-smoke --exec python3 scripts/runs/run_static_projection_campaign.py --stage smoke --config configs/experiments/static_projection_training.json --out runs/static_projection/smoke
```

Expected: exit `0`; direct/static artifact IDs are distinct, expected coverage is nonzero, handshakes succeed, and FIFO cleanup is complete.

- [ ] **Step 9: Run full verification and commit**

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest discover -v
git diff --check
git add configs/experiments/static_projection_training.json configs/designs/ibex_opentitan_real_ip/static_projection/config.json configs/designs/rvx_multicomponent/static_projection/config.json scripts/runs/run_static_projection_campaign.py tests/test_static_projection_campaign.py
git commit -m "feat: integrate static projection training campaign"
```

Expected: full suite passes and the diff check is clean.

### Task 6: Independent Review and Task 6 Readiness Gate

**Files:**
- Modify: `.superpowers/sdd/progress.md`
- Create: `.superpowers/sdd/task-5-report.md`

**Interfaces:**
- Consumes: Tasks 1-5 commits and verification output.
- Produces: approved Task 5 evidence and an explicit empirical-screening readiness decision.

- [ ] **Step 1: Review specification compliance**

Review against `docs/superpowers/specs/2026-07-26-harness-specific-build-design.md` and Task 5 of the main static projection plan. Reject if any fuzz job lacks one completed unambiguous build, artifact substitution is possible, or campaign code bypasses `run_experiment_matrix`.

- [ ] **Step 2: Review quality and regression risk**

Inspect canonical job serialization, deterministic ordering, legacy unique-build compatibility, fail-closed behavior, target-policy separation, and atomic outputs. Record findings with file/line references in `.superpowers/sdd/task-5-report.md`.

- [ ] **Step 3: Re-run acceptance verification after fixes**

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest tests.harness.test_harness tests.harness.test_flow_integration tests.experiments.test_planner tests.experiments.test_rfuzz_adapter tests.experiments.test_report tests.experiments.test_static_portfolio tests.integration.test_experiment_matrix tests.test_static_projection_campaign tests.test_ibex_opentitan_real_ip_target tests.test_rvx_multicomponent_target -v
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest discover -v
git diff --check
```

Expected: focused and full suites pass, the diff check is clean, and no Critical or Important finding remains.

- [ ] **Step 4: Record completion evidence**

Append the exact commit range, focused/full test counts, smoke result, and review verdict to `.superpowers/sdd/progress.md`. Commit only the report and ledger if those paths are tracked project artifacts.
