# P8 source metadata materialization control design

Source design only; no Git subprocess, remote operation, fetch/download, test or heavy process ran. Existing native work is independent and must not be restarted or overlapped. This design creates new source metadata and does not modify the old promisor stores. P6/P7/P8 remain OPEN.

## Exact input contract

Use the lock's declared roots/revisions and `.gitmodules`' declared official URLs together. Contrary to the shorthand “sources.lock URL”, the current lock does not contain these URL fields.

| Component | Root | Exact revision | Official URL from `.gitmodules` |
| --- | --- | --- | --- |
| OpenTitan | `third_party/soc-opentitan` | `fca045df919a26c47e71616b9dac917b1ea4fd07` | `https://github.com/lowRISC/opentitan.git` |
| ZipCPU | `third_party/soc-zipcpu` | `42606d2d6ef55df313772232977621b2d72f0159` | `https://github.com/ZipCPU/zipcpu.git` |

Freeze both input files and this controller's eventual source. Lock SHA is `4caf0ae616e99e3c7cac76a1b04daca41af9bcef0eee3b6b0923fb6bd7e2a29e`; rehash `.gitmodules` at the actual preparation boundary. Review exact Git/tool/env identities separately. Paths below are proposed, not created: new `/root/fanzehui/myfuzz/operations/p8-source-materialization-20261018-attempt1/{control,stores,stage}`. Refuse existing destination, symlink ancestors, hard links and paths outside `/root/fanzehui`; jumpserver only forwards.

## What existing code actually requires

`prepare_p7_i5_snapshot.py:validate_git` is a pure file/topology validator. It rejects any `.promisor` file and any config key named `promisor` or `partialclone` even if its value is false, external config includes/hooksPath, nonempty alternates/commondir and external worktree pointers. It requires HEAD, objects and refs directories, including explicit directory-manifest entries. It does not acquire objects or prove connectivity. Independent stores must therefore be initialized cleanly; setting an old promisor flag to false does not satisfy its admission or object completeness requirements.

`verify_soc_sources.py` uses actual `git -C <root> cat-file blob <revision>:<relative-path>` and byte compares against on-disk content and lock SHA. Root tracking checks use `git -C <base> ls-files --error-unmatch -- <path>`. A bare store alone supplies blob lookup but is not a usable project working tree/status configuration; conversion below builds real nonbare metadata and index. The verifier CLI has `--base-dir`, `--lock` and optional `--elaborate`; it has no component selector. Do not invent `--component`, or invoke the full lock against a deliberately partial staging tree and call unrelated missing roots a materialization failure.

The previous [Ibex preparation](p7-i5-remote-independent-preparation-20261018.md) actually used independent shallow local-file materialization (`--no-local --no-hardlinks --depth 1`), read-tree and connectivity receipts. Its later failure came from losing empty refs directories during transfer. Preserve objects, refs/heads, refs/tags and all other directory modes explicitly, and freeze a new whole map after every metadata overlay. Existing receipts do not validate these two new stores.

## Minimal root-reviewed operation

The future parent takes exact reviewed input/source/tool hashes, writes its PID/argv/environment/start receipt, captures every child Popen/start/stdout/stderr/exit, waits for the same actual child on interruption, and retains failures. No kill/restart or implicit retry/fallback. Record which mutually exclusive path was selected before starting it; an offline failure is retained and a later official fetch gets a new attempt directory/receipt.

Use an isolated empty global Git config file and `GIT_CONFIG_NOSYSTEM=1`, `GIT_CONFIG_GLOBAL=<operation-owned-empty-file>`, `GIT_TERMINAL_PROMPT=0`, `GIT_OPTIONAL_LOCKS=0`; remove inherited GIT_DIR/GIT_WORK_TREE/GIT_OBJECT_DIRECTORY/GIT_ALTERNATE_OBJECT_DIRECTORIES and injected config/namespace variables. Exact wrapper/backend selection must match the reviewed tool receipt. New repositories get no templates/hooks/config includes or alternates from old stores. All commands below are **proposed argv, not executed**; brace labels stand for controller-supplied literal absolute paths/URLs/revisions, not shell eval.

### A. Preferred offline quarantine and snapshot-only repack

A full checkout at the pinned HEAD may already have every snapshot object while older promised history remains incomplete. Copy the old component `.git` bytes and complete directory map to a new private `quarantine/<component>.git`, with original full maps before/after identical and no hard links. No Git subprocess runs against the old store. Quarantine retains the original promisor metadata as evidence; do not treat it as final metadata or repair its flags.

All quarantine Git invocations use command-local `-c protocol.allow=never`, an empty `GIT_ALLOW_PROTOCOL` allowlist, and `GIT_NO_LAZY_FETCH=1`. Scrub config injection/environment overrides as above. Local installed Git documentation explicitly describes `GIT_ALLOW_PROTOCOL` as an allowlist overriding existing protocol configuration; an empty list allows none. `GIT_NO_LAZY_FETCH` is not documented by the inspected local manpage and must not be the only network barrier. A pinned tool's actual option/environment support remains a separately reviewed preparation prerequisite. Any missing-object attempt fails and is preserved, with no implicit network fallback.

Starting from the exact commit SHA, use `cat-file commit <SHA>` to read/rehash its complete commit bytes and extract exactly one root-tree SHA. Traverse each tree breadth-first with `ls-tree -z <treeSHA>`, parse mode/type/OID/name using NUL-safe records, and independently read/rehash each tree's raw bytes and every blob via `cat-file --batch` (length-delimited payloads). Include symlink blobs as objects while refusing filesystem symlinks in the staged copied source. Record gitlinks separately: they are submodule references, not recursively available snapshot blobs. Do not follow commit parents: their omission will be declared by the new shallow boundary. Deduplicate by OID, require actual types/modes, reject malformed names and any missing object. A commit SHA appearing in an index is insufficient.

Only after the entire snapshot is verified, write the explicit sorted unique object list containing the pinned commit, all snapshot trees and all snapshot blobs. Propose these child argv, with object-list stdin and pack stdout captured to operation-owned files:

```
git --git-dir={private_quarantine} -c protocol.allow=never pack-objects --stdout --no-reuse-delta --no-reuse-object
git init --bare --template= {new_bare_store}
git --git-dir={new_bare_store} index-pack --stdin
```

Feed `pack-objects` explicit OIDs, **without `--revs`, `--all`, `--thin` or a filter**. `--no-reuse-delta`/`--no-reuse-object` force reconstruction rather than retaining an unreviewed packed representation. Only the newly generated self-contained snapshot pack is fed to new-store `index-pack`; do not copy old packfiles with unreachable partial history into the final store. Missing old history cannot then cause final fsck to inspect inherited incomplete unreachable objects.

Write the new store's `shallow` file with the exact official pinned commit plus newline as an explicit ancestry boundary, set `refs/heads/pinned` to that same OID and HEAD to that ordinary ref, then run the clean-store object/closure/fsck checks below. Record that this is a newly constructed shallow view of an unchanged official commit, not a rewritten commit or complete history. Neither promisor config keys nor `.promisor` files or alternates are introduced in the clean init. Assert the final object's OID set equals the explicit snapshot list; each object's rehashed content must agree with quarantine and staged working-tree bytes. A failure leaves the private attempt immutable. A later network attempt requires a separately selected new directory and receipt.

### B. Explicit official source fetch

If the root chooses network materialization, create a fresh clean bare store and fetch the exact locked commit with depth1 and no filter. Permit only HTTPS for this chosen transport, with no inherited filter/partial-clone settings. For each component separately:

```
git init --bare --template= {new_bare_store}
git --git-dir={new_bare_store} fetch --depth=1 --no-tags --no-recurse-submodules {official_url} {exact_revision}
git --git-dir={new_bare_store} update-ref refs/heads/pinned {exact_revision}
git --git-dir={new_bare_store} symbolic-ref HEAD refs/heads/pinned
```

A new clean init has no partial-clone filter to inherit; the fetch deliberately includes no `--filter`. Keep server stderr, FETCH_HEAD, shallow bytes and fetched pack identities. Assert FETCH_HEAD and HEAD both resolve to the exact revision, object type commit, and exactly the declared shallow root. If the server refuses fetching that SHA, preserve the failure; do not silently fetch latest/default branch or change the revision. This is full selected-commit tree/blob materialization with a declared shallow ancestry boundary, not full history. No recursive submodule acquisition is implied; any gitlink dependencies needed by the lock require separate reviewed pinned stores.

## Independent clean-store object validation

For each new store, record actual argv/exit/output for these ordinary Git operations:

```
git --git-dir={new_bare_store} rev-parse HEAD
git --git-dir={new_bare_store} cat-file -t {exact_revision}
git --git-dir={new_bare_store} rev-parse {exact_revision}^{tree}
git --git-dir={new_bare_store} rev-list --objects {exact_revision}
git --git-dir={new_bare_store} fsck --full --strict --no-reflogs
```

Independently parse the object traversal and invoke `cat-file --batch-check` and `cat-file --batch` with explicitly supplied object IDs to verify type, size and actual payload reads. Rehash each object's canonical `type + space + decimal-size + NUL + payload` using SHA1 and require its object ID. Reject missing/delta/unreadable objects or wrong blob/tree types. Verify every selected lock/profile/include/license artifact's exact path via `cat-file blob <revision>:<path>` and compare both lock SHA256 and actual staged bytes; retain the resulting per-path receipt. Full tree traversal does not fetch gitlink repositories; record those boundaries explicitly.

Run checks on the **clean new non-promisor store**, not only the old promisor source. Refuse promisor/partialclone keys, `.promisor` files, alternates/commondir, linked configs/hooks and out-of-root paths; retain shallow boundary/provenance as legitimate declared ancestry, not a missing-object repair. Hash all new files and record directory modes. For old component working trees and metadata, compare full file/directory maps before/after, including config, HEAD, refs, indexes and packs. Original metadata/content must remain unchanged; object reads/index presence alone do not prove this.

## Convert into copyable nonbare `.git`

Copy each accepted bare store into the corresponding **new staging component** `.git` as independent regular files, preserving all empty directories. Never overlay the old component's `.git` into the new store. On this new copy only:

```
git --git-dir={stage_component}/.git config core.bare false
git --git-dir={stage_component}/.git --work-tree={stage_component} read-tree {exact_revision}
git -C {stage_component} rev-parse --git-dir
git -C {stage_component} rev-parse HEAD
git -C {stage_component} status --porcelain=v1 --untracked-files=all
git -C {stage_component} ls-files --error-unmatch -- {each_required_relative_path}
git -C {stage_component} cat-file blob {exact_revision}:{each_required_relative_path}
```

`read-tree` initializes the index without `-u` and therefore does not replace the separately verified working-tree bytes. `core.bare=false` is an explicit change on the new metadata copy, unrelated to removing old promisor flags. Do not retain an absolute `core.worktree` pointer; Git discovers the enclosing working tree from `.git`. Re-run clean-store fsck/object checks after conversion. Inspect status rather than assuming it must be empty: missing unselected upstream files show deletions if only a selected working tree was copied. Prefer the complete component tree required by the dependency checklist; regardless, every required path must be tracked and byte-identical. A deliberate selected-tree status has to be recorded and accepted explicitly, not hidden.

Preserve the independently copied project root `.git` and gitlink entries. Component `read-tree` does not add project closure/profile/evidence files to the root index; check root `ls-files --error-unmatch` for required lock/closure/provenance artifacts separately. Retain root HEAD/status receipts without rewriting historical root identity. Invoke existing verifier consumers only in the eventual complete source snapshot, using their actual supported interface; materialization receipts can independently reproduce the same per-path blob/SHA comparisons without importing project code.

Finally run the strict preparer's plan/prepare on the **new post-overlay tree**, independently compare destination full file/directory manifests, and record freeze hash, directory-manifest hash, copy receipt and selected source/tool identities. No file-only tar omission of empty refs is allowed. A later scalar measurement has its own reviewed command/lock/output/cache and acceptance receipts; this metadata operation grants no runtime, timing, fresh, source-consumption or P8 completion claim.

## Git behavior evidence read for this design

Only installed documentation bytes were read: `/usr/share/man/man1/git.1.gz`, `git-pack-objects.1.gz`, `git-index-pack.1.gz`, `git-cat-file.1.gz`, `git-ls-tree.1.gz`, `git-fetch.1.gz` and `git-clone.1.gz`. No Git executable/version command or internet request was made. The pack-objects manual documents ordinary stdin as an object-name list, `--revs` as switching to revision traversal, and `--thin` as omitting required objects; index-pack documents reading pack stdin and building/installing an index. This substantiates the snapshot-only pack approach, while actual remote Git tool/env compatibility and end-to-end receipts remain unverified. The repo's preparer/verifier source checks described above remain the integration contract.
