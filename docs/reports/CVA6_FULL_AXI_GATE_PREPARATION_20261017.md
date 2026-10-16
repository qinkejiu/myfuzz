# CVA6 full AXI native gate preparation

Source-only preparation, 2026-10-17. Native execution remains pending the canonical heavy window.

The gate preserves the existing 650-step store/load/store program and seed 0. It requires two fresh generated sessions, full original RESULT receipts/raw samples, exact offline observer replay, once-only Runner imports, whole-prefix fresh equality with typed execution identity normalization, actual PID/close evidence and binary/cache manifest crosslinks. Pending transactions remain partial; no retirement, source authority or global protocol completion is granted.

Software controls: **25 passed in 5.68s**. Success fixtures use the real wire parser and status=result. Controls reject wrong execution/case/reset/component scopes, binary/manifest/lifecycle mismatch and commands after collector budget exhaustion; failures retain original evidence. Source-only paths prohibit tool launch and artifact construction.

Logs and SHA256 receipts: `evidence/cva6-full-axi-gate-preparation-20261017/`. Independent read-only review: `.superpowers/sdd/cva6-full-axi-gate-source-review.md` (cfb060f), no high/medium findings. No native/build/elaboration ran. Future remote preparation requires independent source copies, source closure validation, canonical environment and separately scheduled lock ownership.

## Independent remote source preparation

Prepared `/root/fanzehui/cva6-full-axi-observer-20261017-attempt1` without acquiring the heavy lock. The 2521-file current working tree snapshot was verified byte for byte after transfer. Four CVA6 repositories were cloned with `--no-hardlinks`; pinned revisions, clean working trees, absent alternates and object link counts of one were checked. All 232 declared closure file hashes match. The pure resolver and source lock verification passed without lint replay. This is source evidence only.

`control/run-native.sh` is stored and unexecuted. It sources the canonical environment, selects the new source first in PYTHONPATH, sets new TMPDIR/OPTIMIZE0, and passes the canonical absolute lock and exact source freeze SHA. The future `run` output does not exist. Complete source verification, freeze, snapshot manifest and control script are mirrored in the evidence directory; the tar remains in the independent remote control directory. System AR bytes were neither read nor copied. Actual CXX/LINK/AR and binary acceptance remain bound to the future native build manifest.
