# CVA6 full AXI native gate preparation

Source-only preparation, 2026-10-17. Native execution remains pending the canonical heavy window.

The gate preserves the existing 650-step store/load/store program and seed 0. It requires two fresh generated sessions, full original RESULT receipts/raw samples, exact offline observer replay, once-only Runner imports, whole-prefix fresh equality with typed execution identity normalization, actual PID/close evidence and binary/cache manifest crosslinks. Pending transactions remain partial; no retirement, source authority or global protocol completion is granted.

Software controls: **25 passed in 5.68s**. Success fixtures use the real wire parser and status=result. Controls reject wrong execution/case/reset/component scopes, binary/manifest/lifecycle mismatch and commands after collector budget exhaustion; failures retain original evidence. Source-only paths prohibit tool launch and artifact construction.

Logs and SHA256 receipts: `evidence/cva6-full-axi-gate-preparation-20261017/`. Independent read-only review: `.superpowers/sdd/cva6-full-axi-gate-source-review.md` (cfb060f), no high/medium findings. No native/build/elaboration ran. Future remote preparation requires independent source copies, source closure validation, canonical environment and separately scheduled lock ownership.
