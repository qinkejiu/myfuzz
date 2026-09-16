# Repository Deep-Cleanup Design

## Goal

Reduce workspace clutter and remove merged worktrees without losing test work that may still be useful. The cleanup prioritizes test reproducibility; transient dependencies, run output, and caches are intentionally discarded.

## Scope

The cleanup covers the root workspace and these merged worktrees:

- `.worktrees/harness-runtime`
- `.worktrees/ibex-protocol-longrun`
- `.worktrees/integration`

Existing user edits to tracked root files, including `README.md` and `.superpowers/sdd/task-A5-report.md`, are outside this cleanup and must not be modified or committed.

## Preservation Rules

Before removing the Ibex worktree, preserve only the files needed to continue or reproduce its testing work:

- `tests/integration/test_soc_real_cva6.py`
- `tests/protocols/test_axi4_processor_memory_adapter_rtl.py`
- `tests/fixtures/soc_cva6_pulp_boot.hex`
- `tests/fixtures/soc_ibex_pulp_loop.hex`
- `tests/integration/rtl/soc_cva6_pulp_tb.sv`
- `configs/soc/cva6-pulp.json`

These files will be validated with the narrowest relevant test commands, then saved in a dedicated Git commit on the Ibex feature branch. The branch will remain after its worktree is removed, so the changes remain recoverable even if they are not merged into `main` during this cleanup.

Documentation edits inside that worktree are not part of the test-preservation commit. SDD briefs, reports, and review diffs are archival records rather than executable test inputs.

The following content is regenerable and will not be archived:

- `runs/` output
- `third_party/` dependency copies
- simulator/build output
- Python bytecode and test caches
- trace artifacts such as `trace_hart_0.dasm`

## Target Layout

User-facing material in the root directory will be grouped as follows:

```text
deliverables/
  presentations/          Final and source PPTX deliverables
docs/
  handover/               Project handover document
scripts/
  maintenance/            Standalone maintenance utilities
archive/
  development/sdd/2026-09/  Untracked SDD briefs, reports, and review diffs
  presentations/2026-09-09/ PPT production workbench files
projects/                  Editable ppt-master project workspaces, retained in place
```

Only untracked SDD artifacts are moved into the archive. The tracked `.superpowers/sdd/task-A5-report.md` stays in place to avoid rewriting an existing user modification.

An archive manifest will record the source worktree or original path for moved SDD artifacts. Files with the same name from different worktrees must be placed under source-specific subdirectories so one cannot overwrite another.

## Worktree Removal Flow

1. Record each worktree's path, branch, commit, dirty state, and disk usage.
2. Run the complete test suite once to establish a pre-cleanup baseline.
3. Run focused tests for the preserved Ibex files.
4. Commit only the six listed test/configuration files on the Ibex branch.
5. Move untracked SDD records from the root and harness worktree into the central archive and write the manifest.
6. Move root presentation, handover, utility, and workbench files into the target layout.
7. Confirm that no meaningful untracked test file remains in any removable worktree.
8. Remove exactly one merged worktree. Regenerable `third_party/` trees and caches inside that worktree are deleted with it.
9. Immediately run the complete test suite from the retained root workspace. Do not remove another worktree unless the suite passes.
10. Repeat steps 8 and 9 separately for each remaining merged worktree.
11. Run the complete test suite once more after all organization and deletion work is complete.
12. Retain all branch references; do not delete feature branches as part of folder cleanup.

## Safety and Failure Handling

- Never use a broad path, glob, workspace root, or home directory as a deletion target.
- Verify each worktree path through `git worktree list` immediately before removal.
- If a focused test fails, preserve the test changes but label the WIP commit and final report with the failing command; do not claim the test is passing.
- If a complete post-deletion test run fails, stop immediately, keep all remaining worktrees, and diagnose the failure before any further deletion.
- If unexpected source or test files appear, stop removal of that worktree until they are classified.
- File moves must preserve existing content byte-for-byte; duplicate names must not be overwritten.

## Verification

Completion requires all of the following evidence:

- focused test results for the preserved Ibex test set;
- complete-suite results for the baseline, after each individual worktree removal, and after final cleanup;
- a Git commit containing exactly the six intended test/configuration paths;
- the retained Ibex branch resolving to that commit;
- `git worktree list` no longer showing the three removed worktrees;
- no root-level PPTX, handover Markdown, `.work/`, or `clear_codex_history.py` left behind;
- archive manifest entries for moved SDD artifacts;
- before/after disk-usage measurements;
- final `git status` showing that pre-existing user modifications are still present and untouched.

## Non-Goals

- Merging the preserved Ibex WIP commit into `main`.
- Rewriting or consolidating existing project documentation.
- Archiving dependency trees, run output, or generated simulator artifacts.
- Deleting feature branches.
