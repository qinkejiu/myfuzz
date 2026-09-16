# Repository Deep-Cleanup Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Preserve test-relevant Ibex work, organize loose project artifacts, and remove three merged worktrees while proving system integrity after every deletion.

**Architecture:** Git is the recovery mechanism for executable test assets: the six approved test/configuration files are committed on `feature/ibex-protocol-longrun` before its worktree is removed. Non-executable review records and presentation assets move into explicit archive/deliverable directories. Each destructive worktree removal is an isolated transaction followed immediately by the complete Python test suite; a failure stops the sequence.

**Tech Stack:** Git worktrees, Bash filesystem tools, Python/pytest, Icarus Verilog, Verilator, Markdown manifests.

## Global Constraints

- Preserve only the six approved Ibex test/configuration paths in the WIP commit.
- Do not modify or commit the existing root edits to `README.md` or `.superpowers/sdd/task-A5-report.md`.
- Do not archive `runs/`, `third_party/`, simulator output, bytecode, caches, or `trace_hart_0.dasm`.
- Remove one worktree at a time and run `pytest -q` immediately afterward.
- If any post-deletion complete test run fails, stop before removing another worktree.
- Keep all feature branch references.
- Use only exact verified worktree paths for destructive operations.

---

### Task 1: Capture the baseline and prove the retained workspace passes

**Files:**
- Read: `.git/worktrees/`
- Read: `tests/`
- Create: none

**Interfaces:**
- Consumes: the current root worktree and Git worktree registry.
- Produces: recorded branch/head/status/disk measurements and a passing pre-cleanup test result.

- [ ] **Step 1: Record exact worktree identities**

Run:

```bash
git worktree list --porcelain
git branch --show-current
git rev-parse HEAD
```

Expected: the root plus `harness-runtime`, `ibex-protocol-longrun`, and `integration` worktrees are listed; every removable path is under `/home/qinkejiu/myfuzz/.worktrees/`.

- [ ] **Step 2: Record status without changing user files**

Run:

```bash
git status --short
git -C .worktrees/harness-runtime status --short
git -C .worktrees/ibex-protocol-longrun status --short
git -C .worktrees/integration status --short
```

Expected: root user edits remain visible; the Ibex test/configuration changes and harness SDD records are visible; integration contains no meaningful uncommitted source or test files.

- [ ] **Step 3: Record initial disk use**

Run:

```bash
du -sh . .worktrees/harness-runtime .worktrees/ibex-protocol-longrun .worktrees/integration
```

Expected: four readable size lines, retained for the final before/after comparison.

- [ ] **Step 4: Run the complete baseline suite**

Run:

```bash
pytest -q
```

Expected: exit status `0`, with no failed or errored tests. If it fails, stop the cleanup before any removal.

### Task 2: Validate and preserve the Ibex test work

**Files:**
- Modify/commit: `.worktrees/ibex-protocol-longrun/configs/soc/cva6-pulp.json`
- Modify/commit: `.worktrees/ibex-protocol-longrun/tests/integration/test_soc_real_cva6.py`
- Modify/commit: `.worktrees/ibex-protocol-longrun/tests/protocols/test_axi4_processor_memory_adapter_rtl.py`
- Create/commit: `.worktrees/ibex-protocol-longrun/tests/fixtures/soc_cva6_pulp_boot.hex`
- Create/commit: `.worktrees/ibex-protocol-longrun/tests/fixtures/soc_ibex_pulp_loop.hex`
- Create/commit: `.worktrees/ibex-protocol-longrun/tests/integration/rtl/soc_cva6_pulp_tb.sv`

**Interfaces:**
- Consumes: the already materialized simulator and `third_party/` dependencies in the Ibex worktree.
- Produces: one recoverable commit on `feature/ibex-protocol-longrun` containing exactly six paths.

- [ ] **Step 1: Run the focused non-opt-in tests**

Run from `.worktrees/ibex-protocol-longrun`:

```bash
pytest -q tests/integration/test_soc_real_cva6.py tests/protocols/test_axi4_processor_memory_adapter_rtl.py
```

Expected: exit status `0`; source-backed cases may be skipped only when their documented prerequisites are absent.

- [ ] **Step 2: Run the real CVA6 opt-in checks while dependencies still exist**

Run from `.worktrees/ibex-protocol-longrun`:

```bash
MYFUZZ_SOC_REAL=1 pytest -q tests/integration/test_soc_real_cva6.py
```

Expected: exit status `0`. If it fails, record the failing test, use the explicitly failing WIP commit message in Step 5, verify the recovery point in Step 6, and then stop this plan before organizing or deleting anything.

- [ ] **Step 3: Stage only the approved paths**

Run from `.worktrees/ibex-protocol-longrun`:

```bash
git add -- configs/soc/cva6-pulp.json tests/integration/test_soc_real_cva6.py tests/protocols/test_axi4_processor_memory_adapter_rtl.py tests/fixtures/soc_cva6_pulp_boot.hex tests/fixtures/soc_ibex_pulp_loop.hex tests/integration/rtl/soc_cva6_pulp_tb.sv
git diff --cached --name-only
git diff --cached --check
```

Expected: exactly the six approved paths are listed and `git diff --cached --check` exits `0`.

- [ ] **Step 4: Inspect the staged payload**

Run from `.worktrees/ibex-protocol-longrun`:

```bash
git diff --cached --stat
git diff --cached -- configs/soc/cva6-pulp.json tests/integration/test_soc_real_cva6.py tests/protocols/test_axi4_processor_memory_adapter_rtl.py tests/integration/rtl/soc_cva6_pulp_tb.sv
```

Expected: no report, documentation, dependency, run-output, or trace path appears.

- [ ] **Step 5: Commit the preserved test work**

If both focused commands passed, run:

```bash
git commit -m "test: preserve CVA6 and AXI4 runtime coverage"
```

If either focused command failed, run instead:

```bash
git commit -m "test: preserve failing CVA6 and AXI4 runtime coverage"
```

Expected: one new commit is created on `feature/ibex-protocol-longrun`.

- [ ] **Step 6: Verify the recovery point**

Run from `.worktrees/ibex-protocol-longrun`:

```bash
git branch --show-current
git show --format=fuller --stat --oneline HEAD
git diff-tree --no-commit-id --name-only -r HEAD
```

Expected: branch `feature/ibex-protocol-longrun`; the commit contains exactly the six approved paths.

### Task 3: Organize retained artifacts and archive SDD records

**Files:**
- Create: `deliverables/presentations/`
- Create: `docs/handover/`
- Create: `scripts/maintenance/`
- Create: `archive/development/sdd/2026-09/root/`
- Create: `archive/development/sdd/2026-09/harness-runtime/`
- Create: `archive/development/sdd/2026-09/MANIFEST.md`
- Create: `archive/presentations/2026-09-09/workbench/`
- Move: root PPTX, handover Markdown, `clear_codex_history.py`, `.work/` contents, and untracked SDD artifacts.

**Interfaces:**
- Consumes: loose root artifacts and untracked SDD records from the root and harness worktree.
- Produces: a shallow root directory and source-separated archives with no name collisions.

- [ ] **Step 1: Create the destination directories**

Run:

```bash
mkdir -p deliverables/presentations docs/handover scripts/maintenance archive/development/sdd/2026-09/root archive/development/sdd/2026-09/harness-runtime archive/presentations/2026-09-09
```

Expected: every destination exists and is under `/home/qinkejiu/myfuzz`.

- [ ] **Step 2: Move root deliverables and maintenance material**

Run from the repository root:

```bash
mv -- 范泽辉-2026.9.9.pptx 范泽辉-2026.9.9-修改版.pptx deliverables/presentations/
mv -- 项目目标与后续任务交接.md docs/handover/
mv -- clear_codex_history.py scripts/maintenance/
mv -- .work archive/presentations/2026-09-09/workbench
```

Expected: no root-level PPTX, handover file, maintenance script, or `.work/` remains; all content exists at the destinations.

- [ ] **Step 3: Move only untracked root SDD artifacts**

Run this exact NUL-safe move from the repository root:

```bash
while IFS= read -r -d '' source_path; do
  mv -- "$source_path" archive/development/sdd/2026-09/root/
done < <(git ls-files -z --others --exclude-standard -- .superpowers/sdd)
```

The Git query returns untracked paths only, so it cannot move `.superpowers/sdd/task-A5-report.md`, which is tracked and user-modified.

Expected: `git ls-files --others --exclude-standard -- .superpowers/sdd` prints nothing afterward, while the tracked modified report remains in place.

- [ ] **Step 4: Move the harness SDD artifacts**

Run this exact NUL-safe move from the repository root:

```bash
while IFS= read -r -d '' source_path; do
  mv -- ".worktrees/harness-runtime/$source_path" archive/development/sdd/2026-09/harness-runtime/
done < <(git -C .worktrees/harness-runtime ls-files -z --others --exclude-standard -- .superpowers/sdd)
```

Expected: the harness command prints nothing afterward; no file is overwritten because the root and harness records have separate destination directories.

- [ ] **Step 5: Write the archive manifest with `apply_patch`**

Create `archive/development/sdd/2026-09/MANIFEST.md` with this content:

```markdown
# SDD Archive Manifest — 2026-09

- `root/`: untracked briefs, reports, progress notes, and review diffs moved from the root worktree's `.superpowers/sdd/` directory.
- `harness-runtime/`: untracked briefs, reports, and review diffs moved from the `feature/harness-runtime` worktree's `.superpowers/sdd/` directory.

Tracked SDD files were not moved. Executable source and test files are not stored in this archive.
```

Expected: the manifest names both sources and explicitly excludes tracked and executable content.

- [ ] **Step 6: Check move integrity and run the complete suite**

Run:

```bash
find deliverables docs/handover scripts/maintenance archive/development/sdd archive/presentations -maxdepth 4 -type f -print
git status --short
pytest -q
```

Expected: all moved files are visible, the pre-existing root modifications remain, and pytest exits `0`. Stop before deletion if it does not.

### Task 4: Remove the harness worktree and test immediately

**Files:**
- Remove: `.worktrees/harness-runtime/`
- Preserve: Git branch `feature/harness-runtime`

**Interfaces:**
- Consumes: an audited harness worktree with its untracked SDD records already archived.
- Produces: a removed worktree, retained branch, and passing complete regression result.

- [ ] **Step 1: Re-audit the exact target**

Run:

```bash
git worktree list --porcelain
git -C .worktrees/harness-runtime status --short
git show-ref --verify refs/heads/feature/harness-runtime
```

Expected: the exact worktree is registered, no meaningful file remains uncommitted, and the branch ref exists.

- [ ] **Step 2: Remove only the harness worktree**

Run:

```bash
git worktree remove --force /home/qinkejiu/myfuzz/.worktrees/harness-runtime
```

Expected: the exact directory and its worktree registry entry disappear; the branch ref remains.

- [ ] **Step 3: Run the complete suite immediately**

Run:

```bash
pytest -q
```

Expected: exit status `0`. If it fails, stop; do not remove either remaining worktree.

### Task 5: Remove the integration worktree and test immediately

**Files:**
- Remove: `.worktrees/integration/`
- Preserve: Git branch `integration/dependency-aware-fuzz`

**Interfaces:**
- Consumes: an integration worktree containing no meaningful uncommitted source or test files.
- Produces: a removed worktree, retained branch, and passing complete regression result.

- [ ] **Step 1: Re-audit the exact target**

Run:

```bash
git worktree list --porcelain
git -C .worktrees/integration status --short
git show-ref --verify refs/heads/integration/dependency-aware-fuzz
```

Expected: only regenerable `third_party/` content may be untracked; the branch ref exists.

- [ ] **Step 2: Remove only the integration worktree**

Run:

```bash
git worktree remove --force /home/qinkejiu/myfuzz/.worktrees/integration
```

Expected: the exact directory and registry entry disappear; the branch ref remains.

- [ ] **Step 3: Run the complete suite immediately**

Run:

```bash
pytest -q
```

Expected: exit status `0`. If it fails, stop; do not remove the Ibex worktree.

### Task 6: Remove the Ibex worktree and test immediately

**Files:**
- Remove: `.worktrees/ibex-protocol-longrun/`
- Preserve: Git branch `feature/ibex-protocol-longrun` and its new test WIP commit.

**Interfaces:**
- Consumes: a committed six-path test recovery point and an audited worktree whose remaining dirty files are non-test reports or regenerable dependencies.
- Produces: a removed worktree, recoverable test commit, and passing complete regression result.

- [ ] **Step 1: Verify the commit and classify every remaining dirty path**

Run:

```bash
git -C .worktrees/ibex-protocol-longrun status --short
git -C .worktrees/ibex-protocol-longrun diff-tree --no-commit-id --name-only -r HEAD
git show-ref --verify refs/heads/feature/ibex-protocol-longrun
```

Expected: `HEAD` contains the six approved paths; no untracked or unstaged test/configuration path remains. Remaining dirty paths are reports, documentation, `third_party/`, caches, or trace output only.

- [ ] **Step 2: Remove only the Ibex worktree**

Run:

```bash
git worktree remove --force /home/qinkejiu/myfuzz/.worktrees/ibex-protocol-longrun
```

Expected: the exact directory and registry entry disappear; `feature/ibex-protocol-longrun` still resolves to the preserved test commit.

- [ ] **Step 3: Run the complete suite immediately**

Run:

```bash
pytest -q
```

Expected: exit status `0`. If it fails, stop and report the failure without claiming cleanup success.

### Task 7: Final integrity and space verification

**Files:**
- Read: repository root, archive, deliverables, Git refs, and worktree registry.
- Create: none

**Interfaces:**
- Consumes: the organized root and three completed removal/test transactions.
- Produces: final evidence that functionality, recovery points, and user edits remain intact.

- [ ] **Step 1: Run the final complete suite**

Run:

```bash
pytest -q
```

Expected: exit status `0`, with no failed or errored tests.

- [ ] **Step 2: Verify worktrees and retained branches**

Run:

```bash
git worktree list --porcelain
git show-ref --verify refs/heads/feature/harness-runtime
git show-ref --verify refs/heads/integration/dependency-aware-fuzz
git show-ref --verify refs/heads/feature/ibex-protocol-longrun
git show --stat --oneline feature/ibex-protocol-longrun
```

Expected: none of the three removed paths appears; all three branch refs exist; the Ibex branch shows the preserved test commit.

- [ ] **Step 3: Verify root cleanliness boundaries**

Run:

```bash
find . -maxdepth 1 -type f -print
git status --short
```

Expected: no root PPTX, handover Markdown, or `clear_codex_history.py`; the original user modifications to `README.md` and `.superpowers/sdd/task-A5-report.md` remain present and uncommitted.

- [ ] **Step 4: Measure reclaimed space**

Run:

```bash
du -sh . .worktrees archive deliverables projects
```

Expected: the three removed worktree directories no longer contribute disk usage; archive size reflects documents and review records only, not dependency or run trees.

- [ ] **Step 5: Report verification evidence**

Report the focused test results, each complete-suite result in deletion order, preserved Ibex commit hash, retained branches, removed paths, moved artifact destinations, and before/after disk measurements.

Expected: the report distinguishes passing, skipped, and failing tests and does not claim success for any command that returned nonzero.
