# BOOM IRQ metadata recovery preparation

Prepared only, 2026-10-17. Operational recovery, compilation, probe enumeration, model and IRQ gate have not run in this preparation. Await exact root execution GO.

Reviewed BOOM helper source is commit 3e9c07b (scripts closure addition, independent review 2cdebba). Its software regression recorded 90 passed in 21.27s. Controller fixture regression recorded 10 passed in 0.04s after RED controls for reuse, source ordering and imported-module identity. These are software results, not IRQ runtime evidence.

Remote base: `/root/fanzehui/boom-irq-metadata-recovery-20261017`. Independent `source` snapshot contains 2564 files; before/after/destination SHA maps agree. Source archive SHA256 is `57434fd909cf0f5e2f7237d33716f65b610c8f77ecc14975900d3a6566d558c8`. Every copied source file has one link and no inode shared with the historical snapshot. PULP standalone `.git` is an actual directory with 39 files and no external Git references. All 316 discovered host dependencies are included. This is a frozen working-tree snapshot, not a clean checkout or a reviewed whole-HEAD claim. The full archive remains locally and remotely alongside the committed file manifests; source-staging trees are not committed.

Remote read-only preparation verified five actual imported BOOM module origins/hashes, four reviewed source pins, 26 historical artifact files against captured archive pins, and actual tool wrapper/binary hashes. It did not execute the model or recovery. Root independently verified ready/control/archive/prepared-state pins and absent operation claim, PID, exit and future outputs; its preflight script/result are included.

Frozen ready SHA256: `566b4c8be6bbe50e4a6ff52d340e243ee5c700022c430772ab3419c8344e0017`.
Controller SHA256: `1d33034e4fd985fde4db5488a98081f064a816fbe2251dde3b7f6f9778e4596b`.
Launcher SHA256: `a00680ec5816dfcfe88637c1adca80ced9b6c8e1acdb9fc71f9c9e48f31b01d3`.
Source manifest SHA256: `c2b8dcc25d2d6eac956d9f94291a6293a6e1fc280083d5726c147013cf385512`.

The future operation uses source-first PYTHONPATH, validates actual imported helper/generator/session paths and bytes before obtaining the recovery API, and exclusively claims the operation before writing PID/state. Reuse refuses without modifying existing state or final artifacts. It independently copies to currently nonexistent `project-finalized`/`artifact-finalized`, audits complete original artifact/source/tool inventories before and after, retains actual argv and exit, and permits only the canonical generator's version query. It never rebuilds or runs the model. Existing attempt2 build0/probe0/finalization1 and old Python identity remain historical facts; new metadata identity is distinct. Any future metadata result remains reused_binary=true, new_cpp_build=false, runtime_verified=false, source_authority=false.

The root review is `.superpowers/sdd/boom-irq-metadata-control-review.md`; it reports no remaining high/medium finding for this exact metadata-only operation. Execution authorization remains separate.
