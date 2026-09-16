# Repository Presentation-Archive Design

## Goal

Remove the remaining presentation-workspace clutter from the repository root while retaining every editable source, export, image, script, and validation record. Remove only disposable test cache and empty tool directories.

## Scope

This cleanup covers:

- `projects/rtlfuzz_dependency_aware_multiharness_ppt169_20260909/`
- `projects/soc_fuzz_ppt_update_ppt169_20260915/`
- `.pytest_cache/`
- empty `.agents/`, `.codex/`, and `.worktrees/` directories

It does not alter source code, test code, Git branches, tracked documentation, final presentation deliverables, or existing user modifications.

## Target Layout

Move the two presentation projects intact:

```text
archive/
  presentations/
    projects/
      2026-09/
        rtlfuzz_dependency_aware_multiharness_ppt169_20260909/
        soc_fuzz_ppt_update_ppt169_20260915/
```

The root-level `projects/` directory is removed only after it becomes empty. No file inside either project is deleted, renamed, deduplicated, or rewritten.

## Preserved Content

The archive retains all project content, including:

- source PPTX files;
- historical PPTX exports;
- images and icons;
- analysis and transformation scripts;
- templates and SVG outputs;
- live-preview material;
- validation reports, readbacks, and logs.

The following existing paths remain in place:

- `deliverables/presentations/`
- `archive/presentations/2026-09-09/workbench/`
- `src/myfuzz/frontend/build/`
- `external_designs/` and its empty submodule directories
- `.superpowers/`

## Disposable Content

Only these paths are deleted:

- `.pytest_cache/`
- `.agents/`, if still empty immediately before deletion;
- `.codex/`, if still empty immediately before deletion;
- `.worktrees/`, if still empty immediately before deletion;
- root-level `projects/`, after both child projects have moved and the directory is empty.

Every directory must be checked immediately before removal. A non-empty tool directory stops its deletion and remains untouched.

## Verification Flow

1. Record the two source project trees, file counts, byte totals, and checksums.
2. Move both project directories to the target archive path.
3. Verify the destination file counts, byte totals, and checksums match the recorded source values.
4. Remove the now-empty root `projects/` directory.
5. Run the core contract and composition smoke tests.
6. Remove `.pytest_cache/` and run the same smoke tests immediately afterward.
7. Check and remove each empty tool directory one at a time, running the same smoke tests after each removal.
8. Verify final root layout, Git status boundaries, archive contents, and disk usage.

The smoke-test commands are:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 tests/contracts/test_contracts.py -q
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 tests/composition/test_address.py -q
```

Both commands must return exit status `0` after every deletion. A failure stops all later deletion.

## Safety Rules

- Use exact paths under `/home/qinkejiu/myfuzz`; do not use broad recursive deletion targets.
- Moving projects is archival relocation, not content deletion.
- Verify equality before removing the empty source parent.
- Do not remove any non-empty `.agents/`, `.codex/`, or `.worktrees/` directory.
- Preserve `README.md` and `.superpowers/sdd/task-A5-report.md` exactly as currently modified.
- Preserve the frontend build because it supports existing tests.
- Preserve empty external-design submodule directories because they express the Git submodule layout.

## Completion Evidence

Completion requires:

- both project directories present under `archive/presentations/projects/2026-09/`;
- matching pre/post project file counts, bytes, and checksums;
- no root-level `projects/` directory;
- no `.pytest_cache/`, `.agents/`, `.codex/`, or `.worktrees/` directory;
- passing smoke-test output after every deletion;
- unchanged tracked source and test files;
- pre-existing user modifications still present in final `git status`.
