# BOOM IRQ one-shot preparation/controller independent review

2026-10-17. Read-only source review plus pure software controls only; no remote, native, build, elaboration, constructor or describe invoked. Scope: d0a449b plan; local preserved final `control/{controller.py,launch.sh,prepare.py,audit-ready.py,test_control.py}`, ready/pins/manifests and remote preparation receipts. The control identifiers below are SHA256 values, not Git commit abbreviations.

## Frozen identities

- controller `8eeb849023137d0319bfa0ccc3f8ffb8f4763b58e4f952881239a6a357be8f36`
- launch `98766db3336248fb150b1449ee26e4fcd3be988dcf178296ae23e1dfd1c6ec1c`
- prepare `329fee817cd64b8b99a7885aaf0c50022fd243ffa59249ebc9620c4f21e168ca`
- audit-ready `084490487b9a8e4e7287e41c96c69631a72d25fa3871440a3437f9e6bda278dd`
- control tests `f46ff086b3c2dc8d49357a78ca731b4d6c74efae1395a40cc7dabc286e7a1bbe`
- final ready `5bde90ac4bc6ae3fe6ffb9bba549421073484b5b515f02d28bf7ee0d40bc7449`
- final-control-pins `95b3d51504136d06d0f7924205d4a9e3a5f546bce1931b825fe8f32395660b15`
- runtime source-freeze `ff5470d2345868bb6f7452b58e38e2ad279c3fc99a66573a3e13cee2e8870167`

Gate source70fdbcb / independent source review869c70b remain separate from these operational controls. Original metadata manifest remains `ec4431b9aa2b75932d9a689d5e5bc1041f6bd25158919bd16e240a428bbd5737`, at the unchanged finalized artifact path.

## Verdict

No high/medium source blocker found in this bounded prepared operation. Exact root GO and externally checked ready/controller/launcher pins are still required. Ready's self-listed hashes are integrity cross-links, not independent authority: the scheduler must compare the final ready SHA above to the actual remote bytes before dispatch. Run with PYTHONOPTIMIZE=0 as the existing gate policy requires. This review is not native evidence or a lock reservation.

The launcher checks all old runtime PID/exit/claim/cache/output state read-only before environment setup and exec. Controller performs exclusive operation.claim before PID/stage writes and refuses reuse without modifying old state. Symlink components are rejected for inventory/copy paths. Independent copies have exact byte inventories, one link, zero shared source inodes and exactly two added reviewed gate files. Original source/artifact bytes and historical metadata/path fields are never overlaid or relabelled; new source is a pinned working-tree snapshot rather than an asserted clean reviewed HEAD.

Actual controller checks final ready control pins, complete new/original/artifact inventories and inode separation, imported module origins/hashes and the gate freeze before spawning. Source-first PYTHONPATH is explicit. Tool selection/path/resolved identity/hashes are checked under fanzehui. The actual inner gate owns canonical flock nonblocking; there is no outer lock or queue/deadlock. A competing holder causes refusal. BOOM binary is reused; only the explicitly authorized later GPIO generated build is possible.

Actual child PID is saved before wait; wait status, poll and argv are saved separately from worker result. Nonzero actual child fails regardless of summary. Exceptions preserve failure and final input/tool audits; a still-live child is awaited rather than killed/restarted. A failed final audit forces worker failure. The current source/gate collector preserves startup/measured native lifecycles and all positive/fresh/suppressed prefixes. Controller summary checks do not replace the inner strict temporal/source/fresh consumers.

Read preparation receipts report actual preparation PID264582/exit0, runtime2566 files (baseline2564 plus2), full source-freeze389, protected artifact88 unchanged, PULP standalone Git39 files, one link and no shared inodes. These were read from preserved receipts; reviewer did not independently rerun remote preparation. No runtime PID/exit is inferred from preparation success.

Independent pure command: `PYTHONPATH=src:. PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -q .superpowers/boom-irq-runtime-gate-20261017/control/test_control.py` —actual exit0, **19 passed in0.08s**. Fake-process success/failure controls verify actual wait-code collection and before/after audits without creating a native process. No native/source/retirement/fullP6/P7 authority is granted.
