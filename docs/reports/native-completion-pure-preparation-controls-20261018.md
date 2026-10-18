# Native completion pure preparation controls

Prepared stable local controls at
`.superpowers/sdd/native-completion-20261018/controls/`. No remote connection,
copy controller, imports, tests, frontend/build/model or heavy process ran.

Extracted exact P6 copy/review and P7 preparation/layout scripts as reference
files with archive/member/hash provenance. Extracted baseline file and
directory maps include8887 files and600 directories, including Git metadata
and empty directories. Existing evidence is unchanged. Baseline actual path is
`/root/fanzehui/myfuzz/operations/p6-native-online-c924aac-20261018-attempt2/project`.

The proposed new `prepare_copy.py` copies the complete frozen baseline, then
applies a separately reviewed explicit overlay tree into a private stage.
It verifies complete byte/mode/directory maps and69 explicit host paths, writes
full-scripts and host-file records, checks baseline/overlay stability, then
renames stage to the new attempt1 project. It retains before/after baseline maps
and a small fsynced receipt even on failure. Bulk byte copies use1MiB chunks
without per-file fsync. Existing attempts are never overwritten. No Git or
archive-based source reconstruction is performed. All paths are confined to
fanzehui; links/special entries and overlay Git changes are refused. Inputs
must be quiescent; the controller does not defend against hostile filesystem
rename races. Failure evidence remains for inspection.

Root still chooses the current complete src/scripts and necessary config/
interface overlay plus complete source closure. The exact overlay file list,
full map and SHA pins are required inputs; no list has been guessed. Add/replace
overlay does not delete baseline files, so root must review any old extra
src/scripts paths before asserting equivalence to current local source.

Directory digest reconciliation is exact: archive member
`remote-copy-control.tar.gz:./final-directories.json` is35036 bytes with file
SHA256 `b16e9bd3b7cabcd0e75ebf051af9a2045ce6dfe600fd7f0cc8035f21389c7393`.
Its parsed map encoded with `json.dumps(sort_keys=True,separators=(',',':'))`
has SHA256 `7cf80b4ce94a31703f41df19307efe7227090ba330130acbe1d1a4a8bf5417ad`.
These identify the same600-directory payload with different encodings.
Baseline file map SHA256 remains
`50145c2408804a76c6ff651cefbb143aae17cd1be18559f79ea6386b510e2cc4`.

Only the new controller's AST was parsed, not executed. Independent review is
pending. Preparation has no gate launcher and acquires no heavy-worker lock;
the separately reviewed later gate must use the canonical nonblocking lock.
No new gate, native completion, source feedback or P6 acceptance is claimed.
