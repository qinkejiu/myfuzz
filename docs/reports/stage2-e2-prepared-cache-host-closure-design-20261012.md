# Prepared-cache host closure: next-package design

Read-only 2026-10-12. Production remains frozen at build02532c9b and v4 is live. The previous18 independent scope tests and34 pipeline checks are historical evidence for that source scope; they do not cover this newly reproduced cache case.

Reviewer reproduced a real cache-path RED: an old artifact-id `_PREPARED_CACHE` entry exists, then a previously absent optional timer module appears **before** a new discovery scope begins. Current `_host_sources()` honestly includes the new file. Scoped `_prepare` checks that new closure, but `_prepared_if_current` validates only files already in the old snapshots and returns the old build identity, which excludes the new host source. Only toolchain lookup was stubbed; this is a generic prepared-cache path failure, not a claim of false certification in the current fresh-artifact native gate.

## Minimal correctness fix

On every prepared-cache reuse, obtain current host closure from the original pinned code-owned accessor. Compare its exact path set and per-path actual bytes/digests with both the cached identity's `host_sources.files` and its captured snapshots. Require the cached host list to be complete/unique/strictly typed; compare exact current host bytes with snapshot bytes, not mtime or only an unchanged old subset. A mismatch invalidates the entry and forces the existing complete regeneration path. Saved identity paths do not drive discovery. A correctly regenerated identity may change after a legitimate file addition; comparing it to an old authenticated Session identity must then reject normally.

This closes the same old subset blindspot **outside a discovery scope**: `_prepared_if_current` must discover current closure itself even when called directly, rather than relying exclusively on `_prepare`'s scoped head guard. Inside a writer/selector scope discovery is already cached and every reuse still checks actual bytes and all recorded probes. Scope probes protect changes *during* an invocation; cached-identity/current-closure comparison protects changes *between* cache creation and a new invocation. Both are required.

Avoid a caller-supplied `current_host` map, saved source-list hint, `already_validated` flag or direct restoration of snapshots as permission. Keep `_prepare` method/context-alias guards before cached reuse and complete per-alias runtime/driver/build regeneration on cache miss. Correct the old comment asserting new imports always require an admitted file to change: optional or package alias modules may appear without changing any old file.

## TDD tests prepared for the next package

1. Preserve reviewer RED with the real cache entry/actual current discovery path. Populate cached host identity/snapshots from the old closure; add an optional timer file before entering scope; assert `_prepared_if_current` returns None and `_prepare` cannot return the old identity.
2. Existing package plus missing `from package import later` module or package-init appearance before a new scope: current map expands, old cache invalidates. Verify actual bytes are incorporated after complete regeneration.
3. Repeat the same tests **without scope** to close the preexisting generic cache blindspot. Do not call only a standalone helper while bypassing the cache return path.
4. Same-length edits with restored mtime, host source deletion, changed import edge, foreign/missing/duplicate cached host row and cached-host/snapshot disagreement invalidate or reject. Unrelated outside-closure files do not silently become admitted sources.
5. Unchanged cache remains reusable, current file bytes are reread, returned identity/snapshots remain detached, toolchain/render hook/artifact mutations still take the existing miss/rejection path.
6. Existing scoped method/context alias replacement and nested/exception cleanup tests stay green. A preexisting cache hit must never bypass the scope guard.
7. A source changes between current discovery and snapshot checking: hard reject or deterministic miss followed by strict regeneration; no partially updated old identity.

## Cost and ownership

Build owner implements `_prepared_if_current` and related private tests after Root releases the next package. Reviewer retains its independent RED; Runner integration owner adds one actual full writer cache-hit/current-closure case; Root runs final pipeline and controls native worker. No current gate files/pins change.

Unscoped cache hits now require actual host discovery unless a separately authenticated preparation-time probe cache is introduced. Prefer the simple correct comparison first and measure it. Scoped calls should reuse the current discovery and retain byte/probe validation, avoiding extra AST scans. If `_prepare` needs the map twice, compute/reuse it only in a bounded private invocation—not through a saved or caller-selected map. A later prepared-cache probe optimization must store discovery-time probe facts as private actual material, compare every existence probe and byte on reuse, and rediscover when any fact changes; it is not part of this minimal fix. Record wall and discovery counts with unchanged and newly expanded closures before any next native run.
