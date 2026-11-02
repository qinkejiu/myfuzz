# Native validation speed implementation plan

> **For agentic workers:** Use subagent-driven-development for the scoped implementation and independent review. Keep native source frozen until every active execution exits.

**Goal:** Reduce repeated host validation work while retaining byte-based source checks, authority, real RTL execution and complete replay.

**Architecture:** Keep the existing build identity and strict host discovery scope. Remove redundant reads on a prepared-cache hit; retain the entry dependency guard and byte/probe reads. Cold preparation keeps a host read before verify/render and its existing final read, so a lazily initialized scope cannot accept a mid-preparation source change as its initial baseline. No additional cache service or public API.

**Tech Stack:** Python, pytest, standard cProfile, existing Verilator harnesses.

## Constraints

- Preserve the dirty workspace and historical evidence; do not commit or reset.
- No mtime-only fast mode, no skipped authority checks, no changed workload rounds.
- Baseline and optimized runs use Timer + Ibex, seed 7, state, one case, 32 rounds, no seconds deadline, full within-invocation replay.
- Profile timings are diagnostic; compare speed using unprofiled runs and report search versus total costs separately.
- Native runs freeze source files. Drafts may be prepared under /tmp while a baseline is live.

## Task 1: Attribute current cost

- [x] Read existing performance evidence and inspect strict build validation with parallel agents.
- [x] Run `python3 -m cProfile -o /tmp/myfuzz-speed-baseline-20261028.pstats scripts/run_dependency_search.py --scenario configs/search/timer-ibex.json --mode original --policy state --cases 1 --seed 7 --output research/input-strategy-audit-20261027/runs/speed-20261028/profile-baseline --cache research/input-strategy-audit-20261027/runs/config-driven-20261028/cache`.
- [x] Observe 278 _prepare calls, 556 host closure reads, 65.11s inclusive host reads out of 190.42s profiled total. Toolchain and cache checks remain separate nested costs, not additive percentages.
- [x] Finish equivalent unprofiled baseline at `runs/speed-20261028/before-timer` before changing source.

## Task 2: One host byte observation on prepared-cache hits

**Modify:** `src/myfuzz/local_harness/build.py::_prepare`.
**Tests:** Existing host source reuse/closure suites, build identity and executable receipt suites; one focused regression asserting branch observation count while checking actual input freshness.

- [x] First add and run the focused regression. Current `_prepare` should exhibit two host callback observations per successful preparation, while the desired branch performs one.
- [x] Keep `_host_source_dependency_guard()` at the preparation entry. Move its adjacent `_HOST_SOURCE_ACCESS()` call after the prepared-cache hit return and before `verify_local_source_lock`. Warm hits use their existing strict host read; cold preparation retains its original before/after host observations.
- [x] Verify cached and full paths still reject source/probe/root/hook drift, including same-size changes with restored mtime and drift between separate admissions. Keep materialized input, binary, manifest and symlink checks unchanged.
- [x] Run the related software gate once and independently review the final diff. Do not add unrelated toolchain/version/path caches.
- [x] Freeze source and run the same unprofiled Timer workload after the change, then strict fresh. Compare selected bytes, case/round counts, actual command behavior and each version's full replay; source-bound hashes may change with the implementation version.
- [x] Record actual search/action/total timings, source hashes and replay outcomes under `runs/speed-20261028/`. Report one paired observation as such, without broad statistical speed claims.

## Ownership

One implementation agent owns build.py and focused host validation tests. Other agents review read-only. Root owns profiling commands, this plan, integration/native checks and the measured report. The intended production change is deletion of duplicate work rather than a new subsystem.

Unprofiled before-timer finished exit 0: search 26.1385s, total 105.0633s, one F4 case at 32 rounds, full replay true. Exact before build.py is retained from the actual processor build input snapshot under runs/speed-20261028/build-before.py. Independent review found and resolved the cold-scope initialization boundary in the design before implementation.

Implementation: exact production diff moves the scoped read below the prepared-cache return. Independent review found no Critical/Important. Root verification: 53 passed + 3 subtests in 0.52s. Agent additionally ran 58 + 3 subtests; new cold verify/render × content/probe/root regressions preserve the lazy baseline boundary. Original RED saw 2 reads rather than 1, and the intentionally incorrect direct-deletion variant failed the cold drift regressions. Optimized native original is running at after-timer; source remains frozen.

Final native verification passed: after original search22.2831s/total98.6155s; strict fresh search22.2311s/total92.7541s. Before original search26.1385s/total105.0633s. This paired original observation reduces search14.75% and total6.14%; selected inputs and semantic hash match exactly. Source and binary bindings/new nonces/clean exits independently verified. See docs/reports/native-validation-speed-20261028.md and runs/speed-20261028/speed-result.json for scope. All native controllers exited.
