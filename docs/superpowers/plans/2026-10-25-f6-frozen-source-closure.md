# F6 Frozen Source Closure Repair Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the Task 8 frozen software gate reproducible from its archive by including every selected test fixture it reads and restoring exact Git-pinned source revisions before execution.

**Architecture:** Add a bounded, generated input set containing shallow Git metadata archives for every Git-pinned component profile and the exact saved RVFI manifest used by the selected software tests. The gate inventory pins those files, validates that the metadata index exactly matches profile declarations, and materializes `.git` metadata only when executing from an extracted snapshot; Git revisions and source byte checks remain strict.

**Tech Stack:** Python 3.12, Git CLI, `tarfile`, SHA-256, pytest.

## Global Constraints

- Preserve every profile's declared `git:<commit>` revision and nested repository pin; do not replace a Git pin with a content hash or bypass `_pinned_source_reader`.
- Include only `runs/task4-ibex-retire/rvfi-export-manifest.json` from the run evidence tree for this selected software closure; do not add the entire `runs/` tree.
- Exclude `.git` directories and `.git` pointer files from ordinary source enumeration; carry Git objects through the separately hashed metadata archive set.
- Every metadata archive and the metadata index must appear in the frozen source map and exact regular-file archive.
- The software command remains `MYFUZZ_RUN_NATIVE_F6=0`; the default native skip policy remains exact.
- No frozen mode runs until a fresh independent review approves the new remote bundle and the `freeze-review.json` matches its hashes.
- Preserve attempt15 and attempt16 failures and evidence without rewriting either attempt.

---

### Task 1: Pin selected run evidence and declared filelists

**Files:**
- Modify: `.superpowers/sdd/compiled-f6-20261024/gates/run_gate.py`
- Test: `tests/integration/test_compiled_f6_gate_supervisor.py`

**Interfaces:**
- Keep `enumerate_inputs() -> list[Path]` and `snapshot() -> dict[str, str]` unchanged.
- Add `runs/task4-ibex-retire/rvfi-export-manifest.json` to the exact explicit input list.
- Treat each profile's `source.filelist` as a declared source file when `_source_directory_policy()` computes directories and files.

- [x] **Step 1: Write failing inventory tests.** The exact RVFI manifest, `.git` pointer exclusion, and declared filelist inclusion have regression coverage.
- [x] **Step 2: Run the focused tests and observe the expected failures.** The inventory tests exposed the missing filelist/manifest closure and pointer leakage before correction.
- [x] **Step 3: Implement the exact inventory rules.** `.git` pointer files are skipped; `source.filelist` and its parent directories are declared; only the RVFI manifest is added from `runs/`.
- [x] **Step 4: Re-run the focused tests.** Inventory regressions pass; the complete gate supervisor module passes **43 tests**.

### Task 2: Generate pinned shallow Git metadata archives

**Files:**
- Create: `scripts/prepare_compiled_gate_source_metadata.py`
- Test: `tests/integration/test_compiled_f6_source_metadata.py`
- Modify: `.superpowers/sdd/compiled-f6-20261024/gates/run_gate.py`

**Interfaces:**
- Generator entry point: `prepare_source_metadata(*, project_root: Path, output_root: Path) -> dict`.
- Index path: `source-git-metadata/index.json`.
- Index schema: `compiled_F6_git_source_metadata_index.v1`; each row has exactly `root`, `revision`, `archive`, and `archive_sha256`.
- Archive paths are `source-git-metadata/repositories/<sha256(root)>.tar.gz`; each archive contains only regular `.git/` metadata files for a shallow clone whose `HEAD` equals the declared revision.

- [x] **Step 1: Write failing generator tests.** Tests cover fixed root/nested repository pins, mismatch refusal, missing root, conflicting pins, malformed pins, symlinked roots, and output-path containment.
- [x] **Step 2: Run the focused test and observe the expected failure.** The initial generator import/API test failed as expected before implementation.
- [x] **Step 3: Implement the generator.** The generator uses the runtime profile-pin parser, shallow-clones exact local commits, rejects symlinked source/output paths, removes remotes, and writes deterministic metadata archives/index.
- [x] **Step 4: Re-run generator tests.** Exact pins, missing roots, mismatched revisions, parent symlink escape, duplicate root revisions, and malformed Git pins are covered and pass.

### Task 3: Validate and materialize frozen source metadata

**Files:**
- Create: `src/myfuzz/integration/compiled_git_source_metadata.py`
- Modify: `.superpowers/sdd/compiled-f6-20261024/gates/run_gate.py`
- Test: `tests/integration/test_compiled_f6_source_metadata.py`
- Test: `tests/integration/test_compiled_f6_gate_supervisor.py`

**Interfaces:**
- Validator: `validate_source_metadata(project_root: Path, frozen_map: dict[str, str]) -> list[dict]`.
- Materializer: `materialize_source_metadata(project_root: Path, frozen_map: dict[str, str]) -> dict`.
- Materialization validates the index against all Git-pinned profile roots and nested repository pins, verifies every metadata archive hash against both the index and frozen source map, extracts only safe regular `.git/` members, and refuses a conflicting existing checkout.
- At `--prepare-freeze`, validate the metadata index and current repository pins before writing the bundle. At `--execute`, materialize missing Git metadata after loading the frozen map and before any child starts.

- [x] **Step 1: Write failing materialization tests.** Tests cover exact HEAD and `cat-file`, preserved bytes, idempotence, archive drift, detached exact HEAD, missing commit object, partial reachable-blob loss through full materialization/rollback, conflicting nested-repository preflight, traversal, symlink, and FIFO archive members.
- [x] **Step 2: Run the focused test and observe the expected failures.** The missing validator/materializer API and a partial-install bug were reproduced before fixes.
- [x] **Step 3: Implement strict validation and materialization.** Exact profile pin coverage, archive hashes/member safety, full `git fsck --full --strict --no-reflogs` connectivity, promisor/partial-clone and remote-tracking-ref rejection, root-path symlink rejection, and rollback/preflight are enforced.
- [x] **Step 4: Integrate with the supervisor.** `source-git-metadata` is inventoried; preparation validates/materializes; execution materializes only after reviewed freeze and command validation and before creating the attempt directory.
- [x] **Step 5: Run focused regressions.** Metadata suite **21 passed** and full supervisor module **45 passed** (**66 passed** total); native mode was not executed.

### Task 4: Freeze, review, execute, and record the corrected remote gate

**Files:**
- Modify after terminal outcome: `.superpowers/sdd/compiled-f6-20261024/tasks/task-8-software.md`
- Modify after terminal outcome: `docs/CURRENT_PROGRESS.md`
- Evidence root: `/root/fanzehui/myfuzz/evidence/f6-task8-attempt17/`

- [x] **Step 1: Generate metadata inputs from the active checkout.** Generated metadata for 16 exact profile-pinned repositories; generator and restored-archive full strict `git fsck` checks passed with no promisor state or remote-tracking refs. Current frozen inventory contains 22,939 regular files including all archives and the RVFI manifest.
- [ ] **Step 2: Prepare a new isolated remote source package.** Include the updated gate sources, one RVFI manifest, all metadata index/archive inputs, and existing vendored `pythonlib`; leave attempts15/16 and `system-20261016` unchanged.
- [ ] **Step 3: Prepare and independently review a new remote freeze.** Require exact source-map/archive/origin/tool/command closure, all declared Git roots, all metadata members regular and safe, expected filelist/manifest inclusion, 12 modes, and absent attempt17 outputs.
- [ ] **Step 4: Run only the reviewed software mode with native F6 opt-out.** Preserve the complete supervisor output, JUnit, executed input archive, and before/after snapshots under the attempt17 evidence directory.
- [ ] **Step 5: Audit the terminal result before updating progress docs.** Record exact pass/fail counts, skips, process reaping, timeouts, input/source/tool stability, and independent raw audit status; do not promote Task8/F6 based on a software-only pass.

