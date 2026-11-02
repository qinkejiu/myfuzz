# Source, documentation and local branch cleanup

> Execute inline in the current checkout: the cleanup target is this existing dirty workspace. Preserve pre-existing changes and record every removal or migration.

**Goal:** Remove uncalled obsolete code, separate historical documentation from current entries, and prune one fully integrated local branch.

**Architecture:** Audit imports and path consumers before each change; preserve exact original bytes in a local recovery store. Keep runtime APIs and evidence inputs intact. Migrate ordinary documentation with rebased links and retain historical source identity.

**Tools:** Git, Python AST, SHA-256, ripgrep, existing Markdown checker and focused unittest suites.

## Constraints

- Do not remove tests, profiles, RTL, archived evidence, current native/F2/F4/F6 implementation, or dirty source files.
- No force deletion, reset, clean, remote push/deletion, or unmerged worktree removal.
- Recorded frozen manifests continue to describe their historical snapshots; this cleanup does not revalidate old gates against new source.
- Recovery store: `runs/repository-organization/20261025-deep/`.

## Tasks

- [x] Inventory Python imports, dynamic path consumers, branch ancestry and working-tree changes.
- [x] Preserve and remove `src/myfuzz/integration/cli.py` and six uncalled one-off scripts: CVA6 plus2/plus3, Ibex LSU/opcode sweeps, old multicomponent comparison and short UART/GPIO campaign. Retain the standalone P5 fault run/replay tool.
- [x] Move nine historical guides/results to `docs/history/`, two references to `docs/reference/`, and the old script task log to `docs/history/`. Rebase links and update ordinary Markdown references without touching frozen evidence.
- [x] Split `docs/CURRENT_PROGRESS.md` into a concise current page and a full historical snapshot; retain incoming heading references through the snapshot.
- [x] Verify the all-branch Git bundle, then delete only the fully merged local `stage2-declarative-cpu-ip-adaptation` branch. Keep other branches/worktrees and all remote refs.
- [x] Run focused CLI/pipeline/reference tests, AST syntax/import checks and documentation comparison; review exact changes against the saved working-tree baseline.

## Validation record

49 focused CLI/pipeline/reference-isolation tests passed after authorized sandbox escalation for the workspace `.git` memory-token lock. The broader static-campaign test module was not rerun; its files and tested launchers were retained. All 1,747 remaining Python files parse; original and destination hashes verify; all 121 broken documentation links predate this batch. Read-only independent review found no actionable findings. See `runs/repository-organization/20261025-deep/verification.json`.
