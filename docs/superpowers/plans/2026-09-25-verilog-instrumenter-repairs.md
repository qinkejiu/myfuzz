# Verilog Instrumenter Repairs Implementation Plan

> **For agentic workers:** Execute each task inline with test-first checkpoints. Keep the existing dirty worktree and archive contents intact.

**Goal:** Fix four verified correctness and safety defects in the Verilog instrumentation path without expanding the supported SystemVerilog grammar.

**Architecture:** Keep the existing source scanner and sticky branch-hit representation. Add a preflight boundary before replacing output trees, isolate each testcase for artifacts that use sticky instrumentation, refuse ambiguous multi-top coverage vectors, and bind build caches to the instrumenter implementation/settings plus the emitted instrumented RTL digest.

**Tech Stack:** Python 3, `unittest`, Verilator/ Icarus where available, current RFuzz simulator artifact/provenance formats.

## Global Constraints

- Original RTL and filelists are read-only inputs; `--force` must not delete any input tree or file.
- Sticky coverage is testcase-local; do not add reset ports or mutate DUT state to clear instrumentation.
- One coverage vector must describe exactly one selected top hierarchy; ambiguous multi-top coverage fails closed.
- Cache reuse must include implementation/settings identity and verify the cached instrumented-output digest.
- Do not alter existing archives, corpus artifacts, or the untracked upstream Ibex tree.
- `.git` is read-only in this environment; do not stage or commit changes.

---

### Task 1: Protect source inputs from output replacement

**Files:**
- Modify: `scripts/source_branch_instrumenter.py`
- Test: `tests/test_source_branch_instrumenter.py`

- [x] Add tests for output equal to, above, or below `project_root`, an output symlink resolving into the project, and external/nested filelist, source, and include inputs that would be removed by `--force`.
- [x] Run the new path-safety tests against the old implementation; they failed after `--force` deleted the temporary source tree/input filelist.
- [x] Resolve and validate output/input paths before replacement; parse filelists before deleting output; reject overlapping project/source/include/filelist paths with stable diagnostics; refuse output symlinks.
- [x] Create/replace output only after analysis and preflight succeed.
- [x] Rerun `tests.test_source_branch_instrumenter` and `git diff --check`.

### Task 2: Keep sticky coverage local to each testcase

**Files:**
- Modify: `src/myfuzz/integration/soc_builder.py`
- Test: `tests/integration/test_rfuzz_simulator.py`
- Test: `tests/integration/test_soc_profile_rfuzz_build.py`

- [x] Add a simulator regression showing isolated executions restart the child and return fresh per-test coverage, while a deliberately non-isolated fake process accumulates its hit state.
- [x] Run the focused simulator test: the non-isolated fake returns cumulative `0x02, 0x06`; isolated executions return fresh `0x02, 0x02`.
- [x] Set the legacy `build_soc_campaign_artifact` result to `isolate_tests=True` and publish the explicit isolation reason in provenance.
- [x] Add an assertion to the opt-in legacy coverage suite; run the profile real isolation test, which passes.
- [ ] Run the legacy assertion through a real matrix artifact. The focused `ibex-pulp` build is blocked before artifact publication because Verilator reports `prim_secded_pkg` unavailable while importing it from `ibex_lockstep.sv`; resolve the source-closure ordering separately, then rerun.

### Task 3: Reject ambiguous multi-top coverage mappings

**Files:**
- Modify: `scripts/source_branch_instrumenter.py`
- Test: `tests/test_source_branch_instrumenter.py`

- [x] Add two branch-bearing tops and assert requesting both with hierarchy propagation refuses to emit a single coverage mapping; retain the existing branch-free multi-top file-map test.
- [x] Fail closed with `multiple-coverage-tops-unsupported` when multiple selected tops yield coverage entries; preserve multi-top operation when no coverage vector is emitted.
- [x] Rerun `tests.test_source_branch_instrumenter`.

### Task 4: Bind profile build cache to instrumentation identity and output

**Files:**
- Modify: `src/myfuzz/integration/soc_builder.py`
- Test: `tests/integration/test_soc_profile_rfuzz_build.py`

- [x] Add tests proving instrumenter source/settings identity and emitted output digest changes change the cache key, and cached instrumented files are checked against their recorded digest.
- [x] Add normalized instrumentation identity (source SHA-256, schema/settings) and deterministic instrumented filelist/source-tree digest to the key and artifact provenance; require the digest to match both before reuse and after copying a cache entry.
- [x] On cache hits, relocate filelist/manifest absolute paths to the current build, validate the closed filelist, and verify the normalized digest remains unchanged.
- [x] Rerun profile cache tests with real Verilator 5.020; the second build reuses the verified cached artifact and `git diff --check` passes.

## Final Verification

- [x] Run `PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest -q tests.test_source_branch_instrumenter tests.integration.test_rfuzz_simulator tests.integration.test_soc_coverage tests.integration.test_soc_profile_rfuzz_build.ProfileAdmissionTest`: 80 tests pass.
- [x] Run the real profile cache and testcase-isolation tests with Verilator 5.020: both pass. Default `tests.integration.test_soc_coverage_run` reports four expected skips without `MYFUZZ_SOC_REAL=1`.
- [ ] Complete the real legacy matrix isolation assertion after fixing the independent Ibex package source-order failure described above.
- [x] Inspect `git diff --check`, changed-file list, and final instrumentation provenance/cache identity fields.
