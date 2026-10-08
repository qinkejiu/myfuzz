# First Step P1–P5 Reproduction and Organization Plan

> **For agentic workers:** Execute these tasks in order in the current session. Keep all saved RTL runs and existing uncommitted work intact.

**Goal:** Audit the current dataflow first step (P1–P5) code, reconcile its documentation, and give it a reproducible, clearly classified entry backed by fresh read-only checks.

**Architecture:** Reuse the repository's existing stage reports and gate scripts. Write new check outputs under `/tmp`, then add a compact reproduction runbook under `docs/reproduction/` and link it from the existing document indexes. Preserve `runs/` paths because reports and replay identities refer to them.

**Tech Stack:** Python 3, repository gate CLIs, Markdown, Git.

## Global Constraints

- Run no RTL build, new fuzz campaign, or full fresh replay during this documentation pass; the user previously reported a memory crash.
- Set a 1.5 GiB virtual-memory limit and run gates sequentially.
- Distinguish fresh read-only re-analysis from historical RTL execution and fresh replay.
- Do not overwrite, delete, or relocate saved run evidence or pre-existing worktree changes.

---

### Task 1: Recheck the stage gates

**Files:** Read `docs/reports/current-dataflow-p{1,2,3,4,5}*` and stage gate scripts. Write transient outputs only under `/tmp/myfuzz-stage1-repro-20261008/`.

- [x] Check P1's CLI and identity tests within the stated memory limit.
- [x] Execute P2's saved-run acceptance gate.
- [x] Execute P3's multi-run acceptance suite.
- [x] Attempt P4's documented `--skip-heavy` acceptance suite; stop after the supposedly skipped heavy comparison reached about 930 MiB RSS, then verify its 48 hermetic tests and historical 8/8 output separately.
- [x] Execute P5's saved-run acceptance suite.
- [x] Record exit code, schema, measured items, source identity limits, and any skipped work for each stage.

### Task 2: Audit code and classify the project

**Files:** Read the active CLI, stage analyzers, online session path, and the relevant reports. Create `docs/reproduction/first-step-code-doc-audit-20261008.md`.

- [x] Map P1–P5 to production modules, acceptance scripts, tests, reports, and saved runs.
- [x] Recheck suspected code defects against actual call sites and record exact impact and verification evidence.
- [x] Classify active code, shared source-fact helpers, historical SoC tooling, frozen evidence, and regenerable caches; move no identity-bound file without a reference audit.

### Task 3: Add one reproduction runbook

**Files:** Create `docs/reproduction/first-step-p1-p5-20261008.md`.

- [x] Provide exact commands, input directories, resource limits, and the fresh outcomes from Task 1.
- [x] Map P1–P5 to their stage reports and explain the evidence boundaries.
- [x] Explain that the runbook rechecks saved artifacts and tests; it does not regenerate their RTL evidence.

### Task 4: Reconcile documents and expose the new indexes

**Files:** Modify `README.md`, `docs/README.md`, `docs/reports/README.md`, `docs/CURRENT_PROGRESS.md`, `docs/CODE_ORGANIZATION.md`, and `QUICKSTART.md` where current text contradicts verified later evidence or a concise link improves navigation.

- [x] Add a single obvious path from project entry to runbook and stage reports.
- [x] Correct stage summary statements that contradict newer P5 evidence, without rewriting historical run artifacts.
- [x] Check Markdown links, audit report references, and `git diff --check`; inspect the final changed-file list.
