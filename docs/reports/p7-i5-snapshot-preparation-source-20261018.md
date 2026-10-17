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

## Independent source review fixes

Review of `6580766` found that aliasing freeze and receipt paths could turn a
completed copy into a publication error, and a failure-receipt write could
mask the original copy exception. Manifest, freeze and receipt paths now must
be distinct. Preflight, destination mkdir, copy and publication errors reach
one outer handler, which attempts one bounded new failure receipt at a safe
external path and re-raises the original exception. If no safe writable path
is available it attempts a bounded stderr diagnostic instead; receipt creation
is best effort, not guaranteed. Existing artifacts are never overwritten.

The manifest also explicitly records an empty private
`.superpowers/sdd/stage2-heavy-worker.lock` as a generated file when the source
selection does not already supply an empty one. This exact code-owned file is
created before the final whole map; it prevents the inner CLI's lock creation
from changing frozen source. The runner's outer canonical heavy-worker lock
remains separate and must be held across execution; creating an empty file
does not grant permission or establish that either lock is unoccupied.

Git config include/includeIf, promisor, partialclone, hooksPath, nonempty
alternates/common metadata and `.promisor` packs are refused. The root-owned
independent Ibex materialization must therefore exclude the old Ibex `.git`
from selection, preserve source identity and original metadata, and overlay
only separately audited independent metadata. That intentional overlay
requires a **new final whole map and receipt** superseding the pre-overlay
freeze; no unchanged-map claim survives it. This script does not perform the
overlay, shallow clone or any Git subprocess.

The actual timer source admission additionally requires the small
`docs/reports/evidence/verilog-probe-pulp-apb-timer` directory. Include it
explicitly alongside the candidate roots above. Source-level fixture/frontend
cache writes remain subject to independent readiness review; neither the
private lock nor this copy establishes that the eventual run is mutation-free.
