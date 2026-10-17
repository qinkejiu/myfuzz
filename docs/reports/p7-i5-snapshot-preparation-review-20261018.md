# Independent source review: P7 I5 snapshot preparer

Reviewed frozen commit `65807667b8957199d6c837eafdc1e9b9e14b497f` and its source report. Script SHA256: `0c89fc422679af29525e5069c6078bdbc3e44f23fa7502fc4bd06f9cbe26448f`. This review used file/commit inspection only; no script execution, project imports, tests, subprocess spawned by the preparer, native activity or remote operations occurred. Only this review document was written.

## Decision

**One medium finding should be closed before using the preparer's failure receipts as reliable operation evidence.** The explicit copy and byte-identity design is otherwise suitable for a reviewed, quiescent source selection. A separate metadata/closure observation below remains relevant to the planned five-root selection. No actual selection manifest or completed copy was supplied in this review, so no concrete closure or destination is approved here.

## M1 — Failed-operation receipt and primary exception are not reliably preserved

In `main()`'s copy `except BaseException`, `write_new(args.receipt, receipt)` is unguarded. If receipt writing fails (permissions, missing parent, occupied path or filesystem failure), that new exception replaces the primary copy/source-race/Git-topology failure. This contradicts the report's unconditional statement that failed copies preserve a failure receipt. Receipt messages are also uncapped.

Additionally, `manifest`, `freeze_map` and `receipt` are not checked for pairwise path inequality. With `freeze_map==receipt` (both initially new), the copy and final checks can succeed and `write_new(freeze_map, actual)` creates the path, then terminal receipt creation fails with FileExistsError. The surviving file is a source map rather than an operation receipt. Source/destination and plan hash remain preserved, but the promised terminal receipt does not exist. The same helper raises pre-copy parser errors and `destination.mkdir()` failures outside the receipt handler, so those paths cannot be audited from a preparer receipt either.

**Requested source fix:** require distinct normalized external manifest/freeze/receipt paths; maintain explicit operation stages beginning after ownership of a new receipt location is established; bound error type/message; attempt failure receipts for admitted preflight and mkdir/copy/final-validation stages; preserve the original exception if receipt writing itself fails. Failures before ownership (existing receipt or invalid/uncreatable output paths) may propagate without writing, but document that limitation. Do not overwrite an existing file or retry copying to conceal the first attempt. No cleanup is requested.

No executed reproduction is claimed: these paths follow directly from ordinary `open('x')` behavior and the source control flow.

## Paths, links and copy behavior inspected

- Include/exclude prefixes must be normalized relative POSIX paths without `..`; absolute and dot prefixes reject. Source/destination reject `..`, symlink path components and mutual containment, and destination must be new.
- Manifest/freeze/receipt paths reject symlink ancestors and placement inside source/destination. File writes are exclusive rather than overwrite. The caller must precreate their external parent directories.
- Enumeration follows only explicit prefixes, prunes explicit excludes and does not follow directory links. Selected symlink files fail the regular-file check. Source files with `st_nlink!=1` and special files reject.
- Each target file is newly created and byte-copied, fsynced, then mode-set. Its regular-file, link-count, size, mode and SHA are compared with the reviewed entry; the original is checked immediately before and after its copy. No hardlink copy or mutation of original source is implemented.
- The source selection is fully re-enumerated after all file copies, and whole-destination file map must exactly equal the expected manifest. Added/removed/changed selected files reject. Directory modes/empty directories are not represented; this is a file-content/mode freeze, not an exact filesystem metadata clone.
- These checks assume a trusted/quiescent namespace. `no_path_links()`/`lstat()` followed by ordinary path-based open/mkdir does not provide adversarial concurrent path-swap protection. Root should keep source and new destination free of concurrent writers during actual preparation; no hostile race guarantee is claimed.

## Git topology, materialization and explicit dependency limits

`validate_git()` requires selected root `.git/HEAD`, handles nested `.git` pointer files, requires each resolved pointer target and HEAD inside the snapshot selection, and refuses nonempty `objects/info/alternates` or `commondir` files. It checks root/nested Git directories for HEAD and an objects directory; external `core.worktree` paths in selected config are rejected. Final destination validation repeats those checks, so an absolute pointer into the original source fails after copying rather than silently borrowing its metadata. The script does not materialize missing Git metadata or rewrite pointers, refs, HEAD, objects or config. Such a source must first be independently materialized and then freshly planned; no such materialization was reviewed here.

**Additional metadata observation:** the validator does not interpret Git `[include]`/`[includeIf] path` or partial-clone/promisor configuration, prove all reachable objects exist, or evaluate the full Git configuration graph. Therefore `HEAD` plus an objects directory is not proof that future Git commands are independent of outside configuration/object acquisition. A config include could point outside the copied selection without triggering this validator. Before authorizing later Git reads, root must inspect/freeze or refuse such configuration and use the reviewed isolated Git environment. This can remain part of the separately stated closure/tool review, but the source report should not describe the preparer as a complete independent Git-dependency proof. The preparer itself invokes no Git command and does not read those included external files.

The reported five candidate third-party roots are operator choices, not automatic dependency discovery. Selecting full `.git`, `src`, `scripts`, `configs`, `tests`, project dependency files and those roots can still omit source-lock artifacts or imports. The script deliberately preserves `closure_reviewed=false` and receipt status `copied_pending_closure_and_tool_review`; those are appropriate limits. Excluded tracked files may remain index deletions and are not silently cleaned.

## Manifest and destination consistency

Planning writes one explicit document containing source/destination, includes/excludes, exact selected file entries and recorded Git HEAD-file contents. Preparation requires the caller-supplied SHA256 of that exact manifest, checks source/destination/schema equality, and rejects override include/exclude flags. It validates expected relative file paths, compares fresh source map and Git HEAD receipts before creation, and checks final destination plus source map afterward. It does not infer dependency roots, change source identities or substitute HEAD for dirty bytes. The final freeze SHA is a hash of the serialized actual file map.

After M1 is fixed, review the actual plan hash and selected closure before copy, then independently audit the final map/receipt and failure state. This review does not authorize a native gate, approve P7 I5 completion or assert the reported remote snapshot is current HEAD.

## M1 follow-up: frozen6b40ef4 source review

**M1 closed in source.** Re-reviewed `6b40ef4a5c13f01d50a1103dabbdffd2dd4c8941`; independent SHA256 read of `scripts/prepare_p7_i5_snapshot.py` after root released the Git freeze is `7bad3c2863209616a2b48dc7b7d273ee8ea9272749c3ffed777e8c5a0d8052b0`. No script, import, test, copy or native execution was performed by this reviewer.

Manifest/freeze/receipt paths are pairwise distinct before preparation. Preflight, destination mkdir, copy and publication exceptions reach an outer `BaseException` handler. It validates a safe new external receipt path, caps the primary message4096 characters, attempts exclusive failure-receipt creation, tolerates receipt/stderr failure and re-raises the original exception. Phase records planning/preparation. Invalid/existing/unsafe receipt paths explicitly produce best-effort stderr rather than overwrite an artifact. This closes the primary-exception replacement and freeze/receipt alias findings; it does not guarantee receipt publication under unwritable storage.

The revised manifest explicitly lists a code-owned empty private `.superpowers/sdd/stage2-heavy-worker.lock` with empty SHA/zero length/mode0600 if not already copied. It is created before the final whole map and must match the exact allowed generated-file declaration. A selected existing private lock must also be empty. This is explicit copy-plan content, not native lock admission or proof of an unoccupied canonical heavy worker.

Git config include/includeIf, promisor/partialclone/hooksPath and `.promisor` packs now reject, supplementing existing alternates/commondir checks. This closes the external-config observation for supported parsed config; it remains a topology/config check rather than a proof that every reachable Git object is present. Separately materialized Ibex metadata overlays require their own audit and a **new final whole map after overlay**, with old metadata excluded explicitly; they cannot inherit the original preparer's freeze hash.

Root later reports pure staging terminal0 with15318 files/790380120 bytes and25 independently materialized Ibex Git files; before/after original source unchanged. Those operation results are root-reported and were not independently recomputed by this source reviewer. No new native authority, P7 I5 negative coverage, actual tool closure or performance capability follows from this source closure.
