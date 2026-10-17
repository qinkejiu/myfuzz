# P7 I5 independent snapshot preparation — design and source record

Status: **source only; not executed**. The new remote `project` is a dirty
42a9ce9 working tree, and its inherited environment points at the old system.
Neither that HEAD nor copying documentation establishes an acceptance snapshot.

`scripts/prepare_p7_i5_snapshot.py` separates a read-only selection plan from
explicit preparation. The operator supplies source root, new destination,
external manifest/freeze/receipt paths, and exact include/exclude prefixes.
Planning hashes the actual selected files; preparation requires the reviewed
manifest SHA and copies exactly those bytes using independent new files.
Destination and source maps are compared, source selections are re-enumerated,
and the final whole-destination map (including Git metadata) is written outside
the destination after all preparation. No Git, frontend, build, test, native,
tool version, or remote subprocess is used.

Candidate third-party roots for the current eight selectors are:

- `third_party/rfuzz/upstream/ibex`
- `external_designs/cv32e40p`
- `third_party/cv32e20_upstream_reference`
- `third_party/soc-pulp-apb-timer`
- `third_party/soc-pulp-apb-gpio`

Include the full selected component trees, not only profile `files`: source
lock artifacts such as LICENSE can be required. Also select `src`, `scripts`,
`tests`, `configs`, actual dependency/project configuration files and `.gitmodules`,
and the full root `.git` directory (about 549 MB in the inspected local tree).
The explicit exclusions can omit caches, outputs and historical configuration
evidence after review; no default exclusion silently changes the selection.
These roots are a candidate set, not a proven transitive closure.

Internal submodule `.git` pointer files are preserved only when their target
metadata is selected inside the snapshot. Standalone `.git` directories are
copied as ordinary independent files. Symlinks, hardlinked source files,
external Git pointers/alternates, and linked-worktree common metadata are
refused. A source with such metadata needs an independently materialized
standalone Git directory before planning; this script does not invent history,
rewrite HEAD, rebuild objects or silently borrow an external object store.

Tool/environment preparation remains separate: this script copies source and
metadata, not tools or caches, and emits no executable wrapper or inherited
environment. The gate runner requires a separately reviewed tool manifest,
source-first imports, external operation TMPDIR/cache, actual lock selection
and explicit execution authorization. No capability or P7 completion is granted.

The preparation command is not a source freeze until the operator has reviewed
the selected closure and manifest hash. Planning deliberately sets
`closure_reviewed=false`; the copy receipt only says
`copied_pending_closure_and_tool_review`. Excluded tracked files can appear as
deletions in the copied repository's dirty map; the script preserves HEAD and
index instead of falsely making that subset look clean. The gate runner's
whole-map check binds these actual subset bytes, and its Git receipts retain
that dirty state.

CLI shape (documentation only, not executed):

```text
prepare_p7_i5_snapshot.py --source SOURCE --destination NEW_DEST \
  --manifest EXTERNAL_SELECTION --freeze-map EXTERNAL_FREEZE \
  --receipt EXTERNAL_RECEIPT --include src --include scripts --include tests \
  --include configs --include .git --include .gitmodules \
  --include EACH_REQUIRED_PROJECT_FILE --include EACH_REVIEWED_COMPONENT_ROOT \
  --exclude EACH_REVIEWED_OUTPUT_OR_CACHE_PREFIX

prepare_p7_i5_snapshot.py --source SOURCE --destination NEW_DEST \
  --manifest EXTERNAL_SELECTION --manifest-sha256 REVIEWED_HASH \
  --freeze-map EXTERNAL_FREEZE --receipt EXTERNAL_RECEIPT --prepare
```

No default prefixes or implicit profile closure are supplied. Both modes are
local filesystem operations when explicitly invoked; the implementation has
not been launched even in planning/help mode. A failed copy preserves its
partial new destination and failure receipt for inspection, without cleanup
or retry. A new destination is required for another attempt.
