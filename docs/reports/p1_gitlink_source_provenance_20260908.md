# P1 Gitlink Source Provenance Report

## Result

Source descriptions can now declare nested repositories as canonical
`{"path": ..., "revision": "git:<40 hex>"}` records. Each checkout must have
the exact declared HEAD and top-level directory. Its nearest declared ancestor
must record the path as a Git tree entry with mode `160000`, type `commit`, and
the same object ID.

Every source byte is checked against the deepest declared repository that owns
its path. This prevents a parent repository pin from appearing to authenticate
files inside a gitlink. Dirty declared files, omitted child pins, wrong child
revisions and independent repositories placed in ordinary tree directories all
fail closed.

Repository entries are sorted for serialization and source identity. Changing
a nested revision changes the identity. With no nested repositories, existing
source hashes and elaboration evidence retain their prior shape and value.

## CVA6 boundary

The fixed CVA6 checkout uses these nested pins:

- `core/cvfpu`: `3eb6afeab2cb33f7d8689222955d0171aeb3a801`
- `core/cvfpu/src/fpu_div_sqrt_mvp`:
  `86e1f558b3c95e91577c41b2fc452c86b04e85ac`
- `core/cache_subsystem/hpdcache`:
  `f404e7ebbda8baa4af3729535f520a6b12a06d03`

The actual explicit 225-source closure passes root, gitlink and per-file blob
verification. The probe then reaches the expected next boundary:
`vendor/pulp-platform/fpga-support/rtl/SyncDpRam.sv` uses a symbolic non-top
port width that the source-only parser cannot represent. Task 7b handles this
by deferring unsupported non-top facts only when compiler elaboration is
explicitly enabled.

## Verification

- Interface and SourceCrawler regression: 55 tests passed in 0.785 seconds.
  Log: `runs/p1_cva6_module_20260908/task7a-final-regression.log`.
- Actual CVA6 boundary probe:
  `runs/p1_cva6_module_20260908/task7a-crawler-probe.log`.
- Independent review: PASS after restoring empty-map identity compatibility and
  adding a valid independent-Git-directory non-gitlink rejection.

This gate proves source ownership across pinned repositories. It does not yet
claim a complete SourceCrawler snapshot or CPU execution.
