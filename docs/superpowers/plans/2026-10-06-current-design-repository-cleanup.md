# Current-Design Repository Cleanup Plan

> **For agentic workers:** Execute this plan inline in the active checkout. Preserve every pre-existing working-tree change and keep a recovery manifest for moved files.

**Goal:** Make the active repository surface match the independent-harness, instruction/dataflow-driven CPU/IP fuzzing design while retaining recoverable historical evidence and all files required by current runtime paths.

**Architecture:** Use `ScenarioRunner`, `ScenarioGenome`, `DataflowRouter`, `DependencyScheduler`, persistent memory, local harness adapters, and real component profiles as the active path. Treat full generated-SoC composition as a separate historical/optional path. Move only files proven unused by source, tests, configurations, scripts, and replay evidence; quarantine rather than permanently delete.

**Tech Stack:** Git status/diff, ripgrep, filesystem hashes, Markdown links, existing repository audit/quarantine tools.

## Global Constraints

- Preserve all tracked edits, staged edits, untracked files, upstream RTL, submodule content, accepted traces, corpora, and current CPU/IP profiles.
- Pre-cleanup snapshot is stored outside the repository at `/home/qinkejiu/myfuzz-cleanup-backup-20261006.MjDhe4/`.
- Do not use `git clean`, `git reset`, recursive deletion, or broad directory removal.
- Keep the original SoC dataflow Word document as a source artifact.
- Do not remove shared `composition` helpers imported by `local_harness` or `scenario`; relocate only after all imports and generated-runtime references have replacements.
- Keep test sources and historical reports as evidence unless a separate path-by-path audit proves they are orphaned; do not run tests for this documentation/file-organization task.

---

### Task 1: Establish the current project entry points

**Files:**
- Create: `docs/CURRENT_DESIGN.md`
- Modify: `README.md`
- Modify: `QUICKSTART.md`
- Modify: `docs/README.md`
- Modify: `docs/REPOSITORY_ORGANIZATION.md`

**Interfaces:**
- Consumes: the user-approved current design and verified runtime boundaries in `docs/LOCAL_HARNESS_RUNTIME.md`.
- Produces: one current-design entry point; older SoC-composition plans and reports are explicitly historical.

- [x] Define testcase input as an instruction-memory image, an external IP source, or an interrupt/dataflow scenario with explicit preconditions and termination observation.
- [x] Document independent CPU/IP harnesses, real RTL outputs, bound inputs, persistent state, local timing, feedback, assertions, and replay.
- [x] Update root, quickstart and docs navigation so `docs/LOCAL_HARNESS_RUNTIME.md` is the implementation-status source of truth.
- [x] Mark the 2026-09-14 full-SoC composition goal as historical without breaking its evidence paths.
- [x] Run `git diff --check` and inspect every changed Markdown link; do not run tests.

### Task 2: Quarantine unrelated workspace utilities and generated sidecars

**Files:**
- Inspect: `scripts/codegen/generate_constrained_harness.py`
- Inspect: `scripts/codegen/generate_lightweight_harness.py`
- Inspect: `scripts/codegen/generate_naive_harness.py`
- Inspect: `scripts/delete_codex_conversations_for_workspace.py`
- Inspect: `scripts/maintenance/clear_codex_history.py`
- Preserve: root `trace_hart_0.dasm` and `SoC内部数据流动与去向.docx:Zone.Identifier`
- Create: `/home/qinkejiu/myfuzz-cleanup-backup-20261006.MjDhe4/excluded-files-manifest.json`

**Interfaces:**
- Consumes: exact path, Git status, reference search, file size, and SHA-256 for each candidate.
- Produces: candidates moved only when unreferenced and unrelated; each move has a reversible source/destination/hash record.

- [x] Search active source, test, config, and documentation references for each candidate.
- [x] Move the unreferenced prototype generators and the two Codex workspace-management scripts outside the project, preserving executable mode and content hashes; keep the Word document and its sidecar as user-provided material.
- [x] Keep the root disassembly trace because the prior cleanup record explicitly reserved trace artifacts; do not infer that it is disposable from its filename.
- [x] Record restoration paths, Git/ignore status, and hashes in the external manifest.
- [x] Leave all RTL traces in place when a report or replay command may depend on them.

### Task 3: Audit the full-SoC implementation path before source removal

**Files:**
- Inspect: `src/myfuzz/integration/soc_builder.py`, `src/myfuzz/integration/soc_matrix_smoke.py`
- Inspect: `src/myfuzz/composition/soc_*.py`, `configs/soc/`, `scripts/generate_soc.py`, `scripts/run_soc_campaigns.py`
- Inspect: `src/myfuzz/local_harness/`, `src/myfuzz/scenario/`, their tests, and replay factories
- Create: `docs/reports/current-design-cleanup-source-audit-20261006.md`

**Interfaces:**
- Consumes: source imports, config references, generated-artifact contracts, evidence replay commands, and working-tree status.
- Produces: a classified source list with `active`, `shared`, `historical-but-reproducible`, or `orphan` decisions and evidence for each decision.

- [x] Keep helpers used by independent harness generation, including source crawling, interface facts, profile elaboration, port dispositions, protocol manifests, and replay support.
- [x] Keep generated-SoC modules out of the active entry point; do not delete or relocate modules with unresolved imports.
- [x] Mark code `orphan` only when no source/test/config/script/replay references remain and its behavior is replaced or unused.
- [x] Move the confirmed unreferenced code-generation prototypes; keep the still-referenced SoC builder path classified as separate historical tooling.

### Task 4: Reduce active documentation clutter

**Files:**
- Inspect: `docs/superpowers/plans/`, `docs/superpowers/specs/`, `docs/reports/`, `QUICKSTART.md`
- Modify: current entry-point links only
- Preserve: archived plans, reports, manifests, and acceptance evidence

**Interfaces:**
- Consumes: Task 1 current-design entry point and Task 3 source classification.
- Produces: a short active reading path; dated historical evidence remains findable but is not presented as the current goal.

- [x] Keep current design, implementation status, protocol/harness extension guide, and latest acceptance report in the active reading path.
- [x] Remove duplicate or broken links from active indexes after verifying their targets.
- [x] Do not delete dated reports or source-backed acceptance records merely because they are old.
- [x] Finish with a Git diff review and a recovery manifest for every moved file.
