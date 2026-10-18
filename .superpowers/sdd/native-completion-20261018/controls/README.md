# Native completion attempt1: pure preparation controls

Prepared locally only. No remote command, controller invocation, project
import, tests, model, frontend, build or tool query has been executed.
`prepare_copy.py` is a proposed controller requiring independent review before
use. No actual preparation/pass result exists.

## Fixed source and destination

- Source: `/root/fanzehui/myfuzz/operations/p6-native-online-c924aac-20261018-attempt2/project`
- New operation: `/root/fanzehui/myfuzz/operations/p6-native-completion-20261018-attempt1`
- New final tree: new operation `/project`, published by same-directory rename
  from `.project-stage` only after exact file/directory validation.
- Existing source file map SHA256: `50145c2408804a76c6ff651cefbb143aae17cd1be18559f79ea6386b510e2cc4`.
- Existing source directory map file SHA256: `b16e9bd3b7cabcd0e75ebf051af9a2045ce6dfe600fd7f0cc8035f21389c7393`.

The original maps contain8887 files and600 directories. The independently
reviewed canonical directory-map content digest is
`7cf80b4ce94a31703f41df19307efe7227090ba330130acbe1d1a4a8bf5417ad`;
this differs from the JSON file's byte digest above by formatting.

## Inputs still to be finalized by root

Root must fix the final source revision and explicit overlay list after all
source changes and reviews. These controls do not guess or freeze that list.
Prepare/upload a separate regular-file overlay tree outside both operations,
plus three immutable reviewed controls:

1. `overlay-paths.json`: the exact list of all overlay file relative paths;
   duplicates, omissions and unexpected additions are refused.
2. `overlay-map.json`: `{files: {relative: {bytes, mode, sha256}}, directories:
   {relative: {mode}}}`, including every parent/empty directory, independently
   frozen from the upload tree. File bytes and modes must match local source.
3. The two extracted original baseline maps, byte-identical to the pinned
   files in `references/`.

Supply both overlay control SHA256 pins as explicit arguments. Root should
include every changed/new Python dependency and every gate/controller script
needed by current source, not only the two new entry files. The final69 explicit
HARNESS host sources are checked from the actual overlaid host_identity AST;
their file hashes are retained separately. They do not replace the dynamic
build import closure: root's overlay selection must include that closure too.
The baseline is copied whole, including complete `src`, `configs`, `scripts`,
all existing Git object/refs metadata, submodule metadata and empty directories.
No git archive/checkout/submodule reconstruction or prefix-filtered scripts
copy is used. Overlay cannot touch any `.git` path and cannot change an existing
directory mode. Unchanged dependency/RTL bytes inherit the verified baseline.
Overlay replaces/adds only: baseline files absent from the local source remain
present. Root must review any such extra `src`/`scripts` file before claiming
equivalence with current local source; this controller has no deletion list.

## Controller interface (documentation, not a launched command)

`python3 prepare_copy.py --baseline-files <remote-reference-baseline-files>
--baseline-directories <remote-reference-baseline-directories>
--overlay-tree <remote-reviewed-overlay-tree> --overlay-map <remote-overlay-map>
--overlay-paths <remote-overlay-paths>
--overlay-map-sha256 <reviewed-sha256>
--overlay-paths-sha256 <reviewed-sha256>`

All supplied paths and every operation path must be below `/root/fanzehui`.
Symlink ancestors, symlink entries, hardlinked files, special files,
noncanonical relative paths and file/directory collisions are refused. There
is no archive extraction in the new controller. Upload handling must enforce
the same constraints. Keep source/overlay/control inputs quiescent throughout
preparation and exclusively own the newly created operation directory; this
controller is not a defense against a hostile process racing filesystem paths.

Byte copies use1MiB blocks and no per-file fsync. File close plus full-tree
rehashing verifies process-visible byte completion; it is not a claim of
power-loss durability for every copied byte. Only the final small receipt is
fsynced. Failed stages are retained for evidence and never silently retried or
deleted. Never reuse or overwrite an existing attempt directory.

## Review and freezing

Before copy: exact whole baseline file and directory maps must match the
archived pins. After copy/overlay: verify every final byte/mode/directory,
including empty directories, and explicit69 host files/full scripts. Before
publication: re-map unchanged baseline and overlay and rehash overlay controls.
Finally: retain source-before/source-after maps and an explicit unchanged
verdict, including on copy failure. `final-file-freeze.json`,
`final-directories.json`, `full-scripts.json` and `explicit-host-files.json`
describe the new operation only. Independent review must re-map final project,
compare both baseline before/after maps, and review the exact overlay diff.
Preparation status is never a source-consumption or native gate pass.

Preparation neither acquires nor modifies the heavy-worker lock. A later
separately reviewed actual gate must acquire the canonical lock
`/root/fanzehui/system-20261016/project/.superpowers/heavy-worker.lock`
nonblocking for its complete heavy lifecycle; busy means refuse, not wait,
delete or replace. No launch script is supplied here and no execution is
authorized by these controls.

## Archived reference provenance

`reference-pins.json` records original archive/member/output hashes. The four
reference scripts were extracted exactly for review and are not launchable
instructions for this new attempt. In particular P7's controller may contain
child launch logic and per-file fsync; neither is carried into the new copy
controller. Baseline maps were extracted from the P6 remote copy archive.
Original archives were read with standard-library tar readers; no old evidence
was overwritten. Proposed new controller was parsed with AST only.
