# Dependency-Aware Fuzz Shared Integration Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Freeze the four exchange contracts, create isolated GitHub-backed worktrees, and provide deterministic integration gates for the composition-core and harness-runtime lanes.

**Architecture:** Shared JSON contracts and fixtures live on the integration baseline. The two implementation lanes consume those contracts without modifying one another's owned files. Integration is performed through a published branch, with one memory-gated Verilator build on the host.

**Tech Stack:** JSON Schema-compatible contract documents, Python `json`, `pytest`, Git worktrees, existing CMake/Verilator frontend, shell-based smoke checks.

## Global Constraints

- Module, instance, port, net, file, directory, and design names are opaque symbols; no textual name heuristics or lookup tables.
- Every component, port, protocol field binding, clock/reset property, and optional/external disposition is explicitly declared.
- RVX reference top is evaluation-only and is inaccessible to generation code.
- Candidate generation is deterministic; Top-K is streamed and bounded.
- The host runs at most one complete Verilator build and memory-gates fuzz workers.
- Every node requires verification, an atomic commit, and a successful GitHub push before completion.
- Do not commit build directories, binaries, waveforms, full fuzz corpora, credentials, or machine-specific absolute paths.

## File Map

Shared integration ownership:

- Create: `schemas/hdl_facts.v2.schema.json`
- Create: `schemas/protocol.v1.schema.json`
- Create: `schemas/composition_ir.v1.schema.json`
- Create: `schemas/candidate_manifest.v1.schema.json`
- Create: `tests/contracts/test_contracts.py`
- Create: `tests/fixtures/contracts/*.json`
- Create: `scripts/check_identifier_policy.py`

Integration-only files:

- Create: `scripts/run_composition_harness_smoke.py`
- Create: `scripts/memory_gate.py`
- Create: `docs/superpowers/integration-checkpoints.md`

## Task I0: Contract Baseline

The four contracts must require `schema_version`, explicit opaque IDs, explicit roles/bindings, provenance, diagnostics, and stable ordering fields. The schemas must reject missing role declarations and duplicate IDs. Protocol IDs select declarative plugins only when explicitly supplied by the user.

- [ ] **Step 1: Write failing contract tests.** Create `tests/contracts/test_contracts.py` with valid round-trip tests and rejection tests for missing versions, missing roles, missing bindings, duplicate IDs, invalid directions, and incompatible major versions.

- [ ] **Step 2: Run the tests.**

Run: `python3 -m pytest tests/contracts/test_contracts.py -q`

Expected: FAIL because the schema fixtures and validator are absent.

- [ ] **Step 3: Add the four schema documents and fixtures.** Put one valid and one invalid fixture per contract in `tests/fixtures/contracts/`. Do not add defaults that infer a role from a symbol name.

- [ ] **Step 4: Implement dependency-free validation.** Add a focused validator under `src/myfuzz/contracts/validation.py` or keep it inside the contract test helper. Validate required fields, types, unique IDs, and version compatibility without depending on target names.

- [ ] **Step 5: Run and publish the node.**

Run: `python3 -m pytest tests/contracts/test_contracts.py -q && git diff --check`

```bash
git add schemas tests/contracts tests/fixtures/contracts
git commit -m "feat(contracts): [I0] freeze versioned exchange schemas" -m "Node: I0\nTests: python3 -m pytest tests/contracts/test_contracts.py -q"
git push -u origin integration/dependency-aware-fuzz
```

## Task I1: Worktree and Memory Gate

**Interfaces:** `python3 scripts/memory_gate.py --claim build --memory-mib N --owner ID --exec COMMAND...` atomically claims the host gate for the blocked workload PID, launches that process, and token-releases after exit. A caller-managed workload may use `--pid PID`; the claim prints a JSON lease and `--release build --owner ID --token TOKEN` releases only that lease. The lock lives outside tracked files and records owner, MiB, workload PID, timestamp, token, and optional caller fields.

- [ ] **Step 1: Write tests** for stale lock reclamation, double claim, non-owner release, and insufficient available memory in `tests/integration/test_memory_gate.py`.

- [ ] **Step 2: Implement `scripts/memory_gate.py`.** Use durable same-directory
  publication, Linux PID liveness with platform-range normalization, bounded
  record I/O and polling, parent-directory `fsync`, and `/proc/meminfo`. Never
  spin without a timeout.

- [ ] **Formal B6 merge prerequisite:** the scheduler branch's `JobClaim` must
  retain the exact gate `Lease`, and `run_job` must pass the same claim to
  `release_job(job, claim)` on every success, failure, and cancellation path.
  Release must pass `claim.lease.token`; owner-only release and legacy fallback
  are forbidden. Add a merged test that round-trips `seed` and
  `candidate_hash` and proves delayed cleanup cannot delete a same-owner
  successor.

- [ ] **Step 3: Create the worktrees from the published baseline.**

```bash
git worktree add .worktrees/composition-core -b feature/composition-core origin/integration/dependency-aware-fuzz
git worktree add .worktrees/harness-runtime -b feature/harness-runtime origin/integration/dependency-aware-fuzz
```

Verify both worktrees point to the same commit and contain no build output.

- [ ] **Step 4: Test, commit, and push.**

Run: `python3 -m pytest tests/integration/test_memory_gate.py -q`

```bash
git add scripts/memory_gate.py tests/integration/test_memory_gate.py docs/superpowers/integration-checkpoints.md
git commit -m "feat(integration): [I1] add worktree memory gate" -m "Node: I1\nTests: python3 -m pytest tests/integration/test_memory_gate.py -q"
git push origin integration/dependency-aware-fuzz
```

## Task I2: Shared Identifier Policy

**Interfaces:** `python3 scripts/check_identifier_policy.py --paths ...` returns nonzero if inference code classifies raw identifier text. Frontend binding, diagnostics, emitter, and source-map modules are the only allowed identifier readers.

- [ ] **Step 1: Write rename and misleading-name tests** in `tests/integration/test_identifier_policy.py`. Require isomorphic graph output after neutral renames and failure when role declarations are missing.

- [ ] **Step 2: Implement the static scanner.** Flag keyword sets, regex classifiers, `startswith`/`endswith` semantic checks, and direct symbol-string comparisons outside the binding allowlist. Explicit user protocol IDs and configuration values are not flagged.

- [ ] **Step 3: Test, commit, and push.**

Run: `python3 -m pytest tests/integration/test_identifier_policy.py -q && python3 scripts/check_identifier_policy.py --paths src/myfuzz/composition src/myfuzz/protocols src/myfuzz/harness`

```bash
git add scripts/check_identifier_policy.py tests/integration/test_identifier_policy.py
git commit -m "test(policy): [I2] enforce opaque RTL identifiers" -m "Node: I2\nTests: identifier policy pytest and scanner"
git push origin integration/dependency-aware-fuzz
```

## Task I3: Joint Smoke Gate

**Interfaces:** `python3 scripts/run_composition_harness_smoke.py --fixture <dir> --out-dir <dir>` invokes both public lane APIs and writes a valid candidate manifest, direct harness, depaware harness, equal raw width, equal coverage universe, and a no-name-policy report.

- [ ] **Step 1: Add `tests/integration/test_joint_smoke.py`** with the output assertions above.

- [ ] **Step 2: Implement the orchestration-only runner.** It may call lane CLIs and existing `run_design_flow.py`; it may not contain connection, protocol, address, or target-specific rules.

- [ ] **Step 3: Run the smoke under the build gate.**

Run: `python3 scripts/memory_gate.py --claim build --memory-mib 3072 --owner I3 --exec python3 scripts/run_composition_harness_smoke.py --fixture tests/fixtures/rtl/small_mmio --out-dir /tmp/myfuzz-joint-smoke`

- [ ] **Step 4: Commit and push.**

```bash
git add scripts/run_composition_harness_smoke.py tests/integration/test_joint_smoke.py
git commit -m "test(integration): [I3] add joint composition harness smoke" -m "Node: I3\nTests: joint fixture smoke"
git push origin integration/dependency-aware-fuzz
```

## Task I4: Target Smoke and Merge Gate

- [ ] **Step 1: Merge the published composition branch** with `git merge --no-ff origin/feature/composition-core` after A's completion node is visible.

- [ ] **Step 2: Merge the published harness branch** with `git merge --no-ff origin/feature/harness-runtime` after its contract tests pass.

- [ ] **Step 3: Run target smoke in order.** Run local structural checks for `configs/designs/ibex_multicomponent_ip`, then remote Ibex + OpenTitan frontend/instrument/toml/harness smoke, then RVX generated-candidate smoke. Every heavy command claims the build gate first.

- [ ] **Step 4: Publish the integration node.**

```bash
git commit --allow-empty -m "test(integration): [I4] pass target smoke gates" -m "Node: I4\nTests: joint fixture, Ibex+OpenTitan smoke, RVX generated smoke"
git push origin integration/dependency-aware-fuzz
```

- [ ] **Step 5: Merge to `main` only after the smoke commit is visible on GitHub.** Use a normal merge; never force-push.
