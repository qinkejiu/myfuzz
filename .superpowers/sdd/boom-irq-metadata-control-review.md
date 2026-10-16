# Independent metadata recovery control review — root

Read-only source and pure preparation audit, 2026-10-17; no recovery/model/compiler invoked by review. Source/helper incremental review remains 2cdebba on3e9c07b. Controls reviewed at control.py SHA1d33034e4fd985fde4db5488a98081f064a816fbe2251dde3b7f6f9778e4596b and launcher a00680ec5816dfcfe88637c1adca80ced9b6c8e1acdb9fc71f9c9e48f31b01d3.

Two root findings resolved before execution:

1. Prior controller/launcher could overwrite PID/state on reuse, then mark an already finalized output incomplete. Fixed by read-only prior-state/output checks and exclusive atomic operation.claim before any PID/state write, shared by direct/shell entry. Reuse returns125 without altering old outputs. Controller final failure marks only an artifact created by its own helper invocation; helper retains its own incomplete marker on partial failure.
2. pythonlib preceded snapshot source in PYTHONPATH. Fixed source-first ordering, delayed API imports until prepared file-byte validation, and explicit imported helper/generator/session origin+SHA checks in this actual process.

The controller checks pinned ready controls, complete source inventory, actual historical archives and original artifact bytes, tool identity, copied source equality and independent inodes. It preserves original inventory before/after including uncaptured build files, and tools/source after; failures retain evidence and do not change the old artifact. New destination names are fixed and separate. Only canonical generation's Verilator version query can run; it does not call build/probe/model/gates or invoke a constructor. Metadata marks reused binary/new_cpp_build=false/runtime_verified=false/source_authority=false.

Owner source-only controls report10passed0.04s; helper regression90passed21.27s. Reviewer did not rerun them. Root independently checked local control pins and remotely checked exact ready SHA566b4c8be6bbe50e4a6ff52d340e243ee5c700022c430772ab3419c8344e0017, all listed control/archive/prepared-state hashes, absent PID/claim/exit/final destinations. Root preflight is archived locally; no operation was started by it. Owner remote source/import/origin preparation reports2564files,316host dependencies,39 standalone PULP Git files and no shared source inodes. This is a frozen working-tree snapshot, not a clean reviewed whole-HEAD claim.

No remaining high/medium finding for the exact metadata-only operation. Source authority, current CPP rebuild and actual IRQ behavior remain unproven; do not promote a metadata result to those claims. Exact root execution GO is separate from this review.
