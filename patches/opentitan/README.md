# OpenTitan source-lock Git preparation

This directory holds the source-lock review patch and its SHA256 manifest for a later Git step. The patch and manifest were moved here from `runs/scenario/acceptance/` on 2026-09-28 so that runtime acceptance evidence remains separate from repository preparation. The move did not stage or commit files.

- `opentitan-source-lock-review.patch`: selected source-lock and profile changes.
- `opentitan-git-preparation-20260928.json`: base commit, patch hash, selected file hashes, and conditional source-gate result. Its `patch_path` points to the patch in this directory.
- `runs/scenario/acceptance/opentitan-source-gate-temporary-index-20260928.json`: retained with acceptance evidence because it records the source-gate result.

Original paths, new paths, sizes, and hashes are recorded in `runs/quarantine/folder-organize-20260928/manifest.json`.
