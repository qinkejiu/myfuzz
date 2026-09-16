# Repository Presentation-Archive Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move both obsolete editable presentation projects into a lossless archive and remove only disposable cache and empty tool directories.

**Architecture:** Each presentation project moves as one intact directory after in-memory file-count, byte-count, and content-hash baselines are captured. Deletions are limited to an empty source parent, `.pytest_cache/`, and three empty tool directories. Contract and composition smoke tests run after every deletion and stop the sequence on failure.

**Tech Stack:** Bash, Git, SHA-256 checksums, Python `unittest`.

## Global Constraints

- Preserve every file beneath both presentation projects byte-for-byte.
- Do not modify or commit `README.md` or `.superpowers/sdd/task-A5-report.md`.
- Preserve `src/myfuzz/frontend/build/`.
- Preserve `external_designs/` and its empty submodule directories.
- Remove a tool directory only when `find <path> -mindepth 1 -print -quit` returns no content.
- Run both approved smoke-test commands after every directory deletion; stop on any nonzero exit status.
- Use only exact paths under `/home/qinkejiu/myfuzz` for moves and removals.

---

### Task 1: Establish the archive and test baselines

**Files:**
- Read: `projects/rtlfuzz_dependency_aware_multiharness_ppt169_20260909/`
- Read: `projects/soc_fuzz_ppt_update_ppt169_20260915/`
- Read: `tests/contracts/test_contracts.py`
- Read: `tests/composition/test_address.py`

**Interfaces:**
- Consumes: the current project trees and root test environment.
- Produces: recorded source counts, byte totals, content hashes, disk usage, and passing 21-test baseline.

- [ ] **Step 1: Confirm exact source and destination state**

Run from `/home/qinkejiu/myfuzz`:

```bash
test -d projects/rtlfuzz_dependency_aware_multiharness_ppt169_20260909
test -d projects/soc_fuzz_ppt_update_ppt169_20260915
test ! -e archive/presentations/projects/2026-09/rtlfuzz_dependency_aware_multiharness_ppt169_20260909
test ! -e archive/presentations/projects/2026-09/soc_fuzz_ppt_update_ppt169_20260915
```

Expected: all commands exit `0`; both sources exist and neither destination exists.

- [ ] **Step 2: Record source metrics**

Run separately in each source project:

```bash
find . -type f -printf '%s\n' | awk '{bytes += $1; files += 1} END {printf "files=%d bytes=%d\n", files, bytes}'
find . -type f -print0 | sort -z | xargs -0 sha256sum | sha256sum
```

Expected: each project reports a nonzero file count, nonzero byte total, and one aggregate SHA-256 value. Retain the four metrics for Task 2.

- [ ] **Step 3: Record initial disk use and Git boundaries**

Run:

```bash
du -sh /home/qinkejiu/myfuzz projects .pytest_cache src/myfuzz/frontend/build
git status --short
```

Expected: disk sizes are readable; the existing modifications to `README.md` and `.superpowers/sdd/task-A5-report.md` remain visible.

- [ ] **Step 4: Run the baseline smoke tests**

Run:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 tests/contracts/test_contracts.py -q
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 tests/composition/test_address.py -q
```

Expected: `Ran 9 tests ... OK` and `Ran 12 tests ... OK`.

### Task 2: Move both presentation projects intact

**Files:**
- Create: `archive/presentations/projects/2026-09/`
- Move: `projects/rtlfuzz_dependency_aware_multiharness_ppt169_20260909/`
- Move: `projects/soc_fuzz_ppt_update_ppt169_20260915/`
- Remove when empty: `projects/`

**Interfaces:**
- Consumes: the two measured source project trees from Task 1.
- Produces: two byte-identical archived project trees and no root-level `projects/` directory.

- [ ] **Step 1: Create the archive parent**

Run:

```bash
mkdir -p archive/presentations/projects/2026-09
```

Expected: the archive parent exists and is empty.

- [ ] **Step 2: Move the exact project directories**

Run:

```bash
mv -- projects/rtlfuzz_dependency_aware_multiharness_ppt169_20260909 archive/presentations/projects/2026-09/
mv -- projects/soc_fuzz_ppt_update_ppt169_20260915 archive/presentations/projects/2026-09/
```

Expected: both destination directories exist; the two source child paths no longer exist.

- [ ] **Step 3: Recalculate and compare destination metrics**

Run separately in each archived project:

```bash
find . -type f -printf '%s\n' | awk '{bytes += $1; files += 1} END {printf "files=%d bytes=%d\n", files, bytes}'
find . -type f -print0 | sort -z | xargs -0 sha256sum | sha256sum
```

Expected: file count, byte total, and aggregate SHA-256 exactly equal that project's Task 1 values. If any value differs, stop and do not remove `projects/`.

- [ ] **Step 4: Remove only the verified empty source parent**

Run:

```bash
test -z "$(find projects -mindepth 1 -print -quit)"
rmdir -- projects
test ! -e projects
```

Expected: all commands exit `0`; only the empty parent is removed.

- [ ] **Step 5: Test immediately after the deletion**

Run:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 tests/contracts/test_contracts.py -q
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 tests/composition/test_address.py -q
```

Expected: `9` and `12` tests pass. Stop before Task 3 on failure.

### Task 3: Remove the pytest cache

**Files:**
- Remove: `.pytest_cache/`

**Interfaces:**
- Consumes: disposable pytest metadata.
- Produces: no pytest cache and a passing post-deletion smoke gate.

- [ ] **Step 1: Verify the exact cache path**

Run:

```bash
test -d /home/qinkejiu/myfuzz/.pytest_cache
git check-ignore -q .pytest_cache
du -sh /home/qinkejiu/myfuzz/.pytest_cache
```

Expected: the path exists, is Git-ignored, and is small disposable metadata.

- [ ] **Step 2: Delete only the cache tree**

Run:

```bash
find /home/qinkejiu/myfuzz/.pytest_cache -depth -delete
test ! -e /home/qinkejiu/myfuzz/.pytest_cache
```

Expected: the exact cache path no longer exists.

- [ ] **Step 3: Test immediately after the deletion**

Run:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 tests/contracts/test_contracts.py -q
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 tests/composition/test_address.py -q
```

Expected: `9` and `12` tests pass. Stop before Task 4 on failure.

### Task 4: Remove empty tool directories one at a time

**Files:**
- Remove if empty: `.agents/`
- Remove if empty: `.codex/`
- Remove if empty: `.worktrees/`

**Interfaces:**
- Consumes: three empty root-level tool directories.
- Produces: a shallower root directory with passing smoke tests after every individual removal.

- [ ] **Step 1: Remove `.agents/` only if it is still empty**

Run:

```bash
test -d .agents
test -z "$(find .agents -mindepth 1 -print -quit)"
rmdir -- .agents
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 tests/contracts/test_contracts.py -q
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 tests/composition/test_address.py -q
```

Expected: `.agents/` is removed and all `21` tests pass. If the directory is non-empty or a test fails, stop.

- [ ] **Step 2: Remove `.codex/` only if it is still empty**

Run:

```bash
test -d .codex
test -z "$(find .codex -mindepth 1 -print -quit)"
rmdir -- .codex
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 tests/contracts/test_contracts.py -q
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 tests/composition/test_address.py -q
```

Expected: `.codex/` is removed and all `21` tests pass. If the directory is non-empty or a test fails, stop.

- [ ] **Step 3: Remove `.worktrees/` only if it is still empty**

Run:

```bash
test -d .worktrees
test -z "$(find .worktrees -mindepth 1 -print -quit)"
rmdir -- .worktrees
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 tests/contracts/test_contracts.py -q
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 tests/composition/test_address.py -q
```

Expected: `.worktrees/` is removed and all `21` tests pass. If the directory is non-empty or a test fails, stop.

### Task 5: Verify final layout and preservation boundaries

**Files:**
- Read: repository root and presentation archive.
- Preserve: `src/myfuzz/frontend/build/`, `external_designs/`, user-modified tracked files.

**Interfaces:**
- Consumes: the completed archive and deletion results.
- Produces: final evidence that all approved content was preserved and only approved disposable paths were removed.

- [ ] **Step 1: Verify root and archive layout**

Run:

```bash
find . -mindepth 1 -maxdepth 1 -printf '%y %f\n' | sort
find archive/presentations/projects/2026-09 -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | sort
```

Expected: no `projects`, `.pytest_cache`, `.agents`, `.codex`, or `.worktrees` entry at root; both project names appear under the archive.

- [ ] **Step 2: Verify preserved paths and final disk use**

Run:

```bash
test -f src/myfuzz/frontend/build/libmyfuzz_frontend.so
test -d external_designs/opentitan
test -d external_designs/rvx
du -sh /home/qinkejiu/myfuzz archive deliverables src/myfuzz/frontend/build external_designs
```

Expected: the frontend library and external-design paths remain; disk measurements are readable.

- [ ] **Step 3: Verify Git boundaries**

Run:

```bash
git diff --name-only
git status --short
```

Expected: no tracked source or test file was changed; the pre-existing `README.md` and `.superpowers/sdd/task-A5-report.md` modifications remain visible; archive and deliverable material remain preserved.

- [ ] **Step 4: Run the final smoke gate**

Run:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 tests/contracts/test_contracts.py -q
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 tests/composition/test_address.py -q
```

Expected: `Ran 9 tests ... OK` and `Ran 12 tests ... OK`.
