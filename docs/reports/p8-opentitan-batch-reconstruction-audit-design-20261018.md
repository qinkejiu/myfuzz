# Planned OpenTitan batch/reconstruction saved-data audit

Source-only design. No new auditor, Git, model, project import, remote collector
or tests have been executed for this design. Actual controller success and
independent saved-data acceptance remain separate. The ZipCPU single-record
auditor and its two original outcomes are unchanged.

## Frozen producer interface

Read actual `materialize_snapshot_reconstructed.py`, SHA256
`fc5faa4abc0bccd561a6ebfea2e779b32b8cdde09ef534bed75c0013ce4ff276`.
Input operation is `p8-source-metadata-inputs-20261018-attempt4`; output is
`p8-source-opentitan-metadata-20261018-attempt2`, both under the existing
`/root/fanzehui/myfuzz/operations/` root. Selected launch requires component
opentitan, `--recover-missing-pinned-files`, pinned `/usr/bin/git` SHA
`2a8c18fbf43da9f692d75474c72bea9dfd796c260b0f3dfe456376abc3bbd668`.
The official revision is fca045df919a26c47e71616b9dac917b1ea4fd07.

The observed design reference is14732 objects/13870 tracked paths with65
originally missing paths. Those are expectations to reproduce independently,
not asserted actual audit counts or a reason to accept incomplete evidence.

## Evidence collection prerequisites after authorization

Retain parent start/terminal, selected launch, exact controller, outer launch
terminal and streams; every numbered child start/terminal/stdin/stdout/stderr;
all child `*.objects.json` batch manifests; source-before/source-after typed
maps; snapshot object/path/gitlink documents; missing plan/final reconstruction
documents; every per-path `recovered-<SHA256(path)>.json`; stage blob-path checks
and complete stage maps. Archive every control file, not a filename subset.

Independently observe current full typed source/stage maps after terminal,
including lstat/readlink bytes without following symlinks. Retain actual bytes
for every reconstructed stage path: regular files are read verbatim; symlinks
are captured as link text, not followed. Selection may use producer missing
records for collection, but independent audit requires the exact missing set.
Original source is observed, never repaired in place.

Inventory all new clean/stage Git metadata before choosing archive members.
Capture HEAD/config/shallow/refs/packed-refs/index and the entire actual
`objects/` store, including `.pack`, `.idx`, **`.rev`**, info files and any
otherwise unexpected file that must be inspected/refused. Do not filter only
pack/idx extensions. No old quarantine pack/source tree copy is needed.
Preserve independent clean typed map plus stage `.git` map. Unexpected
promisor/alternates/commondir files must be refused, not filtered from evidence.

Retain archive SHA/size/member hashes. Safely unpack into a new owned directory
with all regular-file bytes verified, refusing absolute/parent/link members.
After-capture supplements require a separate time, hash and source-map binding;
they cannot be relabeled as terminal-time archive members. Large archives stay
at stable local and remote paths with committed pins and receipt indexes.

## Independent streaming batch parser

Read actual stdin OID lines and raw stdout sequentially. Each command permits
at most128 requests, all distinct valid40-hex OIDs, in exact expected order.
For each request, independently parse one ASCII `OID type size\n` header,
then exactly size payload bytes and one newline; reject missing/type/size/EOF
errors, swapped records and all trailing bytes. Record actual header offset,
payload offset and record-end offset while streaming; never treat a producer
offset as the parser's starting truth.

Rehash SHA1 of `type + SP + decimal-size + NUL + payload` and payload SHA256
for every record. Retain commit/tree/symlink bytes needed by the independent
tree walker; stream other blob content/hash comparisons to avoid loading all
files or all transcripts simultaneously. Compare each producer objects.json
row and requested_objects/store/stdout_file/status against these independent
offsets, types, lengths, identities, hashes and expected retention policy.
This includes clean batches that intentionally retain no payloads in memory.

## Complete binary-tree closure and exact command phases

Independently parse the pinned commit's single root tree. Walk actual binary
trees (`mode SP name NUL raw20-byte OID`), validate safe unique names/modes,
deduplicate tree requests per layer, and derive every blob/symlink/gitlink path
without using ls-tree or producer manifests as enumeration authority. Reject
gitlinks pending a separate boundary. Blob request set is independently
deduplicated/sorted and parsed in bounded batches. Compare derived object and
path documents only after this closure exists.

The command checker models the reconstructed producer's actual phases:
commit batch; per-layer tree batches; deduplicated blob batches; one pack;
clean init/index-pack/ref/HEAD/fsck; sorted all-object clean batches;
batch-all-objects set; stage index/status/128-path ls-files chunks; a separate
complete stage commit/tree/blob closure; final fsck. Do not copy the ZipCPU
single-object, per-blob cat-file command order. Require all child records to
be consumed exactly once, contiguous and in receipt order, with actual rc0,
strict argv/cwd, matching input/output hashes and actual PID/start bindings.

Join actual pack-objects stdout byte-for-byte to index-pack stdin and the
unique materialized clean/stage pack. Require identical clean/stage idx/rev
bytes, validate pack/idx checksum/object names/count and exact independently
derived snapshot-only object set. Validate .rev framing/checksum/index binding
if implemented; otherwise preserve exact .rev bytes/hash and label that
semantic parsing boundary. Independently rehash all actual clean and stage
Git batch object reads. Do not claim independent pack decompression unless a
separate implementation actually does it.

## Original gaps and reconstruction joins

Compute original working-file set from full source typed map, excluding only
its actual `.git/` subtree. It must be a subset of the independent pinned tree,
with every present file's kind/bytes/hash and executable bit matching that
tree; extras or changed present files refuse acceptance. The missing set is
derived as tree minus original working set. Compare that complete set against
the missing plan, parent fields and final/per-path reconstruction receipts.

For each missing path, require absent original before/after/current entry,
`original_lstat=missing`, pending-to-reconstructed status transition and the
exact producer receipt filename SHA256 of path text. Its capture reference
must point to a real original quarantine blob record parsed above, matching
OID/type/size/SHA and independently derived payload offset. Read exactly those
payload bytes and terminator; compare byte-for-byte with separately captured
actual reconstructed stage file/link bytes. Preserve ordinary file Git mode
or exact safe link text. Check the stage's independently reconstructed second
closure also contains the identical OID/content, ignoring only the different
capture-location field between original/stage closure records.

Final actual stage must contain all tracked paths and no extra worktree files;
every saved stage-git-blob-path-check row must agree with actual typed file
map, independent blob bytes/hash/kind/mode and its second Git-read closure.
Complete source before/after/current maps must remain equal, including the65
gaps if that expectation is reproduced. This establishes a reconstructed stage,
not an originally complete source working tree.

## Scope and independent result

Check pinned controller and selected Git metadata; closed-offline child argv,
no fetch/clone/remotes/hooks/fsmonitor execution; official one-revision shallow
boundary/HEAD/ref and dependency-free configs. Environment scrub is established
by reviewed pinned code unless actual per-child environment measurements are
separately captured; these are distinct evidence classes.

Save actual audit start/end/rc/stdout/stderr and exact auditor/archive pins.
Any failure remains immutable, with a specific data difference. Do not widen
checks or reuse output paths to hide an evidence collection omission. Even a
successful audit grants only staged OpenTitan component source metadata, not
whole P8 project, runtime/scalar integration, models, fuzzing or performance.
