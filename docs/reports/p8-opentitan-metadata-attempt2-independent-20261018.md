# OpenTitan attempt2: independent reconstructed component metadata audit

The staged OpenTitan component source metadata passes the independent
saved-data audit. This accepts a reconstructed component snapshot only;
whole P8 project preparation, scalar/runtime adapters, model execution,
fuzzing and5×/performance acceptance remain ungranted.

The actual producer parent463069 returned0 after485 Git children, each with
an actual zero terminal returncode. Its reviewed controller SHA256 is
`fc5faa4abc0bccd561a6ebfea2e779b32b8cdde09ef534bed75c0013ce4ff276`;
selected Git SHA256 is
`2a8c18fbf43da9f692d75474c72bea9dfd796c260b0f3dfe456376abc3bbd668`.
The pinned official revision is fca045df919a26c47e71616b9dac917b1ea4fd07.

## Independent result

Actual saved-byte audit ran2026-10-18 at09:31:47.877–09:31:50.641UTC,
returncode0 and stderr empty. It independently reconstructed14732 Git objects
and13870 tracked paths from commit/binary-tree bytes, with bounded128-record
batch framing, exact request order, independently derived offsets and every
object's Git SHA1/content SHA256. Recorded manifests were cross-checks rather
than tree-enumeration authority. All485 child command phases, input/output
hashes, actual results and selected launch fields matched the expected closed
offline controller sequence. All original and staged Git object material was
independently rehashed; the second complete stage closure matched the first.

The original working tree lacked65 pinned paths. Its present files were
unchanged and matched pinned blobs; its complete typed source file/directory
maps agree before/after and with later independent observation, including those
gaps. Each missing path's actual reconstructed stage bytes was separately
captured, then compared byte-for-byte to the original Git batch payload at the
independently parsed offset. Missing plan/final/per-path receipts matched the
exact independently derived missing set. This establishes the new stage's
complete snapshot, not a claim that the original working tree was complete.

New clean/stage metadata was captured in full, including index, complete object
store, `.pack`, `.idx`, `.rev` and directory/file modes. Complete metadata sets
and modes match independent current maps. Unique clean/stage packs exactly
match actual pack-objects stdout/index-pack stdin; indexes and reverse indexes
agree, checksum/object-name sets match the snapshot, and reverse-index framing,
checksum and permutation checks pass. This is not independent pack
decompression; object-content verification uses independently rehashed actual
Git-read payloads joined to exact recorded pack material. Single pinned shallow
boundary, HEAD/ref, dependency-free config, no promisor/alternates/shared store,
empty Git status and final zero fsck were checked.

The stage has13878 total files, including its Git metadata, and2267 directories.
Its complete typed file-map SHA256 is
`ca6edabf56ac26c89adc0bbe33e89beefc76aee8c89af8171635fe128540980e`;
directory-map SHA256 is
`61004483e762ecd8da7c5a62a466bca43ff24d2e4962787540f1cbcd1c7a59b5`.

## Collection, extraction and boundaries

Authorized two-hop read-only collection ran09:26:21–09:27:50UTC, rc0,
stderr empty. It set PYTHONOPTIMIZE=0/PYTHONDONTWRITEBYTECODE=1, used only
standard-library reads, and ran no Git, models or project imports. Its current
inventories are explicitly later than the producer terminal; they are not
relabeled as terminal-time process measurements. Parent absence and exact
operation/inputs/component/child and recovered-payload counts were joined.

Safe extraction ran09:31:42–09:31:47UTC, rc0. Archive SHA/size were checked
before/after; all original members and file hashes were checked, links/special
members and unsafe paths were refused, files were created exclusively and
file/directory modes were preserved. Only the final small extraction receipt
was fsynced; no per-file power-loss durability is claimed. Auditor SHA256:
`89a1d3225a808d4e93775beb493bedb433ebf3cd9f1156ec293102b506aa72cc`.
The audit stdout/JSON SHA256 is
`371bf1357a4fed8ec879010dcb6480b0b888de9c214ebd9573b59a8963e1e568`.

Environment enforcement is supported by the reviewed pinned controller's
GIT_* scrub and exact closed-offline argv, not by a separate captured per-child
OS environment. The independent audit ran no Git, model, repository-network
fallback, project imports, frontend or tests; it did not mutate producer data,
retry the metadata operation or alter a check after execution.

## Evidence availability

Small receipts, exact collector/extractor/auditor/controller sources, member
hash index, actual child terminal index, typed-map pins and independent result:
`docs/reports/evidence/p8-opentitan-metadata-attempt2-20261018/`.

Original319025663-byte archive remains locally, excluded from Git:
`/home/qinkejiu/myfuzz/docs/reports/evidence/p8-opentitan-metadata-attempt2-20261018/actual-remote.tar.gz`.
SHA256 `18661a048d60b707629cc5bef162fa2e5172181825d2825689d4da69d6654866`.
Remote originals remain under
`/root/fanzehui/myfuzz/operations/p8-source-opentitan-metadata-20261018-attempt2`,
with selected inputs in `p8-source-metadata-inputs-20261018-attempt4`.
Raw Git outputs and recovered stage payloads remain in that pinned archive.
Earlier failed attempts remain separate outcomes.
