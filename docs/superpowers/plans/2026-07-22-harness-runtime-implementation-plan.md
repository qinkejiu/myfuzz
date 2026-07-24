# Dependency-Aware Harness Runtime Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Compile explicit protocol declarations and composition facts into memory-bounded direct, candidate-direct, and dependency-aware fuzz harnesses, then run fair RVX and Ibex+OpenTitan coverage experiments without identifier heuristics.

**Architecture:** Python owns protocol DSL validation, plugin compilation, static CSR dependency overapproximation, dynamic field-group shrinking, harness manifests, scheduling, and reports. Generated SystemVerilog is a structural projection of the frozen composition IR; runtime inputs keep one identical raw bit width across baselines. Existing flow scripts remain orchestration-only.

**Tech Stack:** Python 3 standard library, SystemVerilog templates, existing rfuzz/Verilator flow, JSON contracts, `pytest`, Linux `/proc` memory accounting.

## Global Constraints

- No module, port, file, directory, target, keyword, regex, prefix, suffix, or abbreviation heuristic; roles, protocol IDs, fields, clock/reset properties, and fuzz dispositions are explicit declarations.
- Protocol plugins are selected only by declared protocol IDs. Unsupported protocol versions fail with a diagnostic; no silent fallback.
- Static dependency analysis is an overapproximation. Dynamic shrinking may remove groups only after reproducible bounded replay; inconclusive groups remain enabled.
- `flat_direct`, `candidate_direct`, and `candidate_depaware` use the same raw input width, seed, cycle budget, and coverage universe for comparison.
- At most one complete Verilator build runs on the host; fuzz workers claim the shared memory gate and release it on all exits.
- No reference top is consumed by generation. RVX reference SoC is evaluation-only; Ibex+OpenTitan has no reference top.
- Every node runs targeted tests, `git diff --check`, creates an atomic commit, and pushes its branch commit to GitHub before the next node.

## File Map

- Create: `src/myfuzz/protocols/model.py`, `catalog.py`, `compiler.py`, `plugins/*.json`.
- Create: `src/myfuzz/dependency/graph.py`, `static.py`, `csr.py`, `dynamic.py`, `replay.py`.
- Create: `src/myfuzz/harness/abi.py`, `direct.py`, `depaware.py`, `templates/*.sv`.
- Create: `src/myfuzz/experiments/scheduler.py`, `jobs.py`, `coverage.py`, `report.py`.
- Create: `tests/protocols/*.py`, `tests/dependency/*.py`, `tests/harness/*.py`, `tests/experiments/*.py`.
- Modify: `src/myfuzz/scripts/frontend_manifest_to_rfuzz_toml.py`, `src/myfuzz/scripts/run_design_flow.py`.
- Create declarative data: `configs/experiments/rvx_generated/*.json` and `configs/experiments/ibex_opentitan/*.json`.

## Task B0: Consume Frozen Contracts

- [ ] **Step 1:** Add fixtures and `tests/harness/conftest.py` loading protocol, composition IR, and candidate manifest contracts from integration node I0.
- [ ] **Step 2:** Run `python3 -m pytest tests/contracts tests/harness -q`; expected harness collection failures only until B1 exists.
- [ ] **Step 3:** Commit and push:

```bash
git add tests/harness/conftest.py
git commit -m "test(harness): [B0] consume frozen contracts" -m "Node: B0\nTests: contracts and harness pytest"
git push -u origin feature/harness-runtime
```

## Task B1: Protocol DSL and Explicit Plugins

**Interfaces:** `load_protocol_catalog(path) -> ProtocolCatalog`, `compile_protocol(binding, facts) -> CompiledProtocol`, and `protocol_input_fields(compiled) -> tuple[InputField, ...]`.

- [ ] **Step 1:** Write failing tests for ready/valid MMIO, APB3/APB4, AXI4-Lite, OBI, and TL-UL host/device subsets; assert explicit field directions, widths, reset behavior, and unsupported-version diagnostics.
- [ ] **Step 2:** Add declarative plugin JSON for those protocol IDs. Each field has an opaque stable ID, direction, width expression, optional/required status, and legal adapter declarations.
- [ ] **Step 3:** Implement typed dataclasses and width-expression validation. A binding references a plugin ID and declared port IDs; raw RTL names are never inspected.
- [ ] **Step 4:** Run `python3 -m pytest tests/protocols -q`; publish:

```bash
git add src/myfuzz/protocols tests/protocols
git commit -m "feat(protocols): [B1] compile explicit protocol plugins" -m "Node: B1\nTests: protocol pytest"
git push origin feature/harness-runtime
```

## Task B2: Static Dependency Overapproximation

**Interfaces:** `build_static_graph(facts, compiled_protocols) -> DependencyGraph` and `to_csr(graph) -> CsrGraph`.

- [ ] **Step 1:** Test declared protocol field groups, RTL data/control edges, clock/reset exclusion, adapter edges, external endpoints, and deterministic CSR ordering.
- [ ] **Step 2:** Implement field-group nodes and CSR adjacency. Include every structurally possible edge and preserve evidence provenance; cap groups at 64 with a deterministic diagnostic when coalescing is required.
- [ ] **Step 3:** Run `python3 -m pytest tests/dependency/test_static.py tests/dependency/test_csr.py -q`; commit `[B2]` and push.

## Task B3: Dynamic Shrink With Replay

**Interfaces:** `shrink_groups(static_graph, replay_fn, budget) -> ShrinkResult` and `replay_fn(seed, enabled_groups, cycles) -> ReplayObservation`.

- [ ] **Step 1:** Test identical-seed replay, one-group-at-a-time removal, reset/timeout inconclusive handling, coverage-loss veto, 64-group cap, and static fallback.
- [ ] **Step 2:** Implement bounded differential replay. A group is removed only when the target coverage signature and required liveness predicates are preserved across the configured repeat count. Preserve static graph when replay is inconclusive.
- [ ] **Step 3:** Run `python3 -m pytest tests/dependency/test_dynamic.py tests/dependency/test_replay.py -q`; commit `[B3]` and push.

## Task B4: Harness ABI and Three Projections

**Interfaces:** `build_harness(manifest, mode) -> HarnessArtifact`, `raw_width(manifest) -> int`, and `coverage_universe(manifest) -> str`.

- [ ] **Step 1:** Write failing tests that require identical raw width and coverage-universe ID for `flat_direct`, `candidate_direct`, and `candidate_depaware`, with stable field maps and explicit clock/reset handling.
- [ ] **Step 2:** Implement `abi.py` field packing/unpacking and SV templates. `direct.py` drives every declared fuzzable endpoint; `depaware.py` projects protocol-valid fields and enables only retained dependency groups. Candidate-direct uses the generated top but no dependency filter.
- [ ] **Step 3:** Emit diagnostics for unbound fields, multiple drivers, width mismatch, and illegal reset values; never infer special inputs from names.
- [ ] **Step 4:** Run `python3 -m pytest tests/harness -q`; commit `[B4]` and push.

## Task B5: Existing Flow Integration Without Name Tables

- [ ] **Step 1:** Add a regression test showing a clock called `wire_17` and reset called `data_3` are handled when explicitly declared, while missing declarations fail.
- [ ] **Step 2:** Remove `CLOCK_NAMES`, `RESET_NAMES`, and `ACTIVE_LOW_RESET_NAMES` from `frontend_manifest_to_rfuzz_toml.py`. Read clock/reset roles and fuzz dispositions from the validated candidate manifest; preserve existing output shape.
- [ ] **Step 3:** Update `run_design_flow.py` to pass manifest paths and candidate mode explicitly, without target conditionals.
- [ ] **Step 4:** Run `python3 -m pytest tests/harness/test_flow_integration.py -q`; commit `[B5]` and push.

## Task B6: Memory-Aware Experiment Scheduler

**Interfaces:** `plan_jobs(manifests, host_memory_mib, max_workers) -> tuple[Job, ...]`, `claim_job(job) -> JobClaim`, and `release_job(job, claim)`; `JobClaim.lease` is the exact gate `Lease` capability.

- [ ] **Step 1:** Test one-build serialization, RSS-based worker limits, stale claim recovery, deterministic job order, and cleanup on failure.
- [ ] **Step 2:** Implement scheduler integration with `scripts/memory_gate.py`;
  record owner, requested MiB, PID, seed, and candidate hash. Store the exact
  gate `Lease` in the returned `JobClaim` and pass that same claim to
  `release_job(job, claim)` on success, failure, and cancellation;
  `release_job` must pass `claim.lease.token`, never owner-only authority or a
  legacy fallback. Before the scheduler branch is merged, add a combined test
  that round-trips `seed` and `candidate_hash` and proves delayed cleanup
  cannot remove a same-owner successor lease. Do not store corpora in Git.
- [ ] **Step 3:** Run `python3 -m pytest tests/experiments/test_scheduler.py tests/experiments/test_jobs.py -q`; commit `[B6]` and push.

## Task B7: Declarative RVX and Ibex+OpenTitan Experiments

- [ ] **Step 1:** Add experiment JSON containing source lists, explicit component/port/protocol declarations, generated-candidate count, seeds, cycle budget, equal raw width, and coverage metric. RVX may name an evaluation-only reference command; Ibex+OpenTitan must omit any reference-top field.
- [ ] **Step 2:** Validate both configs through the public loaders. No Python source may branch on RVX, Ibex, OpenTitan, or module names.
- [ ] **Step 3:** Run `python3 -m pytest tests/experiments/test_configs.py -q`; commit `[B7]` and push.

## Task B8: Coverage Collection and Report

**Interfaces:** `collect_branch_coverage(run_dir) -> CoverageSummary`, `compare_modes(results) -> ComparisonReport`, and `write_report(report, path)`.

- [ ] **Step 1:** Test equal-time normalization, branch-universe identity, missing/partial result diagnostics, and candidate ranking without hardcoded target labels.
- [ ] **Step 2:** Implement streaming summaries and JSON/CSV output containing seed, cycles, raw width, candidate hash, mode, branch totals, covered branches, and provenance.
- [ ] **Step 3:** Run `python3 -m pytest tests/experiments/test_coverage.py tests/experiments/test_report.py -q`; commit `[B8]` and push.

## Task B9: Harness Lane Gate

- [ ] **Step 1:** Run `python3 scripts/check_identifier_policy.py --paths src/myfuzz/protocols src/myfuzz/dependency src/myfuzz/harness src/myfuzz/experiments`.
- [ ] **Step 2:** Run `python3 -m pytest tests/contracts tests/protocols tests/dependency tests/harness tests/experiments -q`.
- [ ] **Step 3:** Run the small fixture smoke with `scripts/memory_gate.py`; verify all three harness modes have equal raw width and coverage universe.
- [ ] **Step 4:** Publish:

```bash
git commit --allow-empty -m "test(harness): [B9] pass harness runtime lane gate" -m "Node: B9\nTests: policy scanner; protocol/dependency/harness/experiment pytest; fixture smoke"
git push origin feature/harness-runtime
```

The lane is eligible for integration node I4 only after the remote completion commit is visible.
