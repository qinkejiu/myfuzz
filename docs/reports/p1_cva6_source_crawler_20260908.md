# P1 CVA6 SourceCrawler Report

## Result

The official fixed-revision `core/Flist.cva6` now runs directly through
SourceCrawler. Three explicit variables replace only braced filelist tokens:

- `CVA6_REPO_DIR=.`
- `HPDCACHE_DIR=core/cache_subsystem/hpdcache`
- `TARGET_CFG=cv64a6_imafdc_sv39`

The parser tokenizes filelist text before substitution, so variable values
cannot create new options or comments. It does not read process environment
variables. Quoted paths, nested filelists, compact `-I` options and
`+incdir+` lists retain source-root anchoring. Undefined, unbraced, recursive,
unsafe or option-shaped values fail closed.

When compiler elaboration is explicitly enabled, unsupported source-only port
widths, types and unpacked shapes may be omitted for any module. Other parser
errors still fail. Missing non-top facts remain unavailable to endpoint binding,
so this deferral cannot create an inferred interface.

## Actual fixed CVA6 run

- Official Flist: 225 source files and seven include roots.
- Verified closure: 317 files across the root plus three pinned repositories.
- Source scan: 207 modules and 865 supported source-only port facts.
- Compiler evidence: all 13 `cva6` top ports.
- Stable warning evidence: 464 warnings in seven classes, zero errors at runner
  acceptance.
- Snapshot content hash:
  `sha256:c5c43bf31209c575fd472111b074077b6a4bc4910c68501f13b66da5a04efe75`.
- Full SourceCrawler wall time: about 6.4 seconds under nice 15/JOBS=1.

Result: `runs/p1_cva6_module_20260908/task7b-crawler-result.json`.

## Verification

- Contracts, interface descriptions and SourceCrawler: 81 tests passed in
  0.835 seconds.
- Nested quoted/root-anchor focused test: one test passed.
- Actual full run log:
  `runs/p1_cva6_module_20260908/task7b-crawler-final.log`.
- Independent review: PASS after closing option-token injection and quoted/
  compact-option root anchoring findings.

This completes source provenance and physical top-port evidence for the chosen
CVA6 configuration. Full AXI semantics, runtime packed-input projection and CPU
execution remain later gates.
