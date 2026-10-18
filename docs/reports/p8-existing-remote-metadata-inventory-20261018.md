# P8 existing remote Git metadata inventory

2026-10-18 read-only inventory: **none of the inspected existing stores resolves the non-promisor metadata preparation requirement**. Expected revisions are visible, but all twelve available stores retain `remote origin promisor=true`, `partialclonefilter=blob:none` and promisor pack markers. No materialization, fetch, configuration correction or source transfer was performed. P8 scalar attribution has not run; P6/P7/P8 remain OPEN.

The [dependency checklist](p8-scalar-remote-dependency-20261018.md) and local `configs/soc/sources.lock.json` SHA `4caf0ae616e99e3c7cac76a1b04daca41af9bcef0eee3b6b0923fb6bd7e2a29e` select these exact revisions:

| Component | Expected revision | Pack files per available store | Pack bytes total |
| --- | --- | --- | ---: |
| OpenTitan | `fca045df919a26c47e71616b9dac917b1ea4fd07` | 2 | 82,525,951 |
| ZipCPU | `42606d2d6ef55df313772232977621b2d72f0159` | 2 | 31,495,898 |
| Ibex | `34b0705760ef3dfa00e99637432473d2be8f22f3` | 5 | 37,381,431 |

The known three component `.git` paths were inspected under each of:

| Existing root | Three metadata paths |
| --- | --- |
| `/root/fanzehui/myfuzz/project` | Available; all promisor=true |
| `/root/fanzehui/myfuzz/dma-uart-project` | Available; all promisor=true |
| `/root/fanzehui/myfuzz/dma-uart-rx-project` | Available; all promisor=true |
| `/root/fanzehui/system-20261016/project` | Available; all promisor=true |
| `/root/fanzehui/myfuzz/dma-continuous-verification-20261017` | All three direct known paths missing |

Paths relative to each root are `third_party/soc-opentitan/.git`, `third_party/soc-zipcpu/.git`, and `third_party/rfuzz/upstream/ibex/.git`. Available entries resolve to in-place directories, with no Git pointer indirection observed. The four available worksets have identical per-component config hashes and pack filenames/sizes; this is not proof that their files are independent inodes or their pack bytes identical. No alternates file or shallow file was observed in these stores. The verification directory's absent direct paths do not establish absence of other nested layouts; no unapproved recursive search was performed.

Every available store has HEAD equal to its expected revision and the expected SHA found in a v2 pack index. Loose refs and packed refs, pack/index/promisor/rev names and sizes, index SHA256, config SHA256 and sanitized promisor/filter metadata are retained in the [read-only receipt](evidence/p8-existing-remote-metadata-20261018/readonly-receipt.json). Index presence proves only that the index lists that object ID. This inventory did not decompress/verify pack objects, traverse commit/tree/blob closure, resolve delta chains, validate index/pack checksums or run Git connectivity/blob checks. It therefore establishes neither complete needed objects nor full history. Removing promisor metadata would not supply missing objects.

The next separately reviewed preparation can examine whether existing pack bytes contain the needed pinned commit/tree/blob closure and working-tree bytes, then materialize an independent new store with explicit object/provenance receipts and freeze its whole file/directory maps. It must preserve all old stores and refuse lazy network acquisition. That work is not executed or authorized by this inventory result; no current candidate is declared ready for strict copy or scalar execution.

Collection used `ssh jumpserver` → `ssh root@192.168.5.70 python3 -`, streaming a standard-library reader through stdin with no remote file creation. All resolved metadata paths were constrained to `/root/fanzehui`. No Git subprocess, project import, download of source/pack files, remote mutation, model, build, heavy lock or tool query ran. Only metadata and pack-index reads were performed; the current native gate/copy paths were not touched. Config bytes were hashed but remote URLs were not exported. Config hashes remained equal on the reader's before/after checks; no full source stability claim is made.

Receipt SHA256: `9c2b96a288b4ef7d64867c9804944ddb6ad9c3b0df74a068f1b462cfc2548d4e`. It also retains the local reader SHA, exact SSH argv and successful transport return code. This report is layout/object-index evidence, not a source-lock, connectivity or runtime acceptance result.
