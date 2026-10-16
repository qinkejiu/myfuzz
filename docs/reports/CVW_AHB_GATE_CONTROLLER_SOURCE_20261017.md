# CVW AHB isolated source and controller preparation

Source-only work. No remote connection, remote write, tool version query, elaboration, DUT build, model or native gate was performed. Local software controls execute only tiny Python children that exit immediately; their PID/exit receipts are not native results.

## Isolated source boundary

The independently reviewed gate is commit `7e1deb5` (root review `ebeed69`). Before the next shared session edits, an independent local source copy was made at `/tmp/cvw-ahb-gate-frozen-20261017-source`, based on reviewed `dc14fa3`, including the reviewed storage-probe generation and BOOM gate source changes. It contains source/config/scripts/tests, the exact required historical fixture artifacts, CVW source/config and Caliptra source, plus independently copied main and nested Git metadata. The early unreviewed controller script/test were explicitly excluded from that source snapshot; the finalized controller is a separate control artifact.

The complete file map contains 11421 entries and 576886434 regular-file bytes. Its SHA256 is `75244d6c7b7e6490ece1c70c20d3e143f9791804dd8f2a247f6e4d088af0dce9`. Every regular file has link count one; internal symlinks are documentary entries and external/unresolved links reject. All three Git directories are self contained and have no external alternates. Main Git used an independent reflink/file copy; nested Git used independent file copies. No hardlinks were created. The copied tree initially failed real saved-facts admission because source-lock also requires the Caliptra LICENSE, beyond profile RTL paths; its exact pinned file was added, the complete map was regenerated, and the RED receipt is retained. The corrected isolated copy passed all 39 gate controls in 14.53s. The complete file map remained unchanged after these controls. Both profile read sets (243 CVW, 38 Caliptra inputs including lock artifacts and include roots) exactly match the reviewed source.

The complete host freeze exactly matched the live reviewed source at capture and has SHA256 `c02134412a742eccde99746af5487f81c2f77f09a7cf20250ce37f2077762e8f`. Later shared HEAD edits do not enter this snapshot. Durable freeze/map/receipt files are under `evidence/cvw-ahb-gate-20261017/`. This is local source preparation, not a remote snapshot or native result.

## Controller contract

`scripts/cvw_ahb_gate_control.py` defaults to printing/writing a source-only plan. Explicit `--execute`, the exact host-freeze SHA and complete snapshot-map SHA are required for its future execution path. Production base paths are confined to `/root/fanzehui`; local tests replace that boundary explicitly to exercise controller wiring.

A one-shot exclusive operation claim precedes preflight and child issuance. Repeated claims, existing output, symlinks and hardlinks reject. The controller validates source-first PYTHONPATH, PYTHONDONTWRITEBYTECODE=1, PYTHONOPTIMIZE=0, actual Python optimization disabled, and the independent TMPDIR. Source/module origin must be the declared independent project. Complete source maps and self-contained Git metadata are checked before the actual child.

**Only the gate acquires the canonical heavy lock, exactly once and nonblocking.** The controller takes no heavy lock and never queues or restarts a child. Its durable claim/started/terminal records carry actual controller/child PID, command, exit and poll status. An observation timeout writes a still-live receipt and continues observing the same handle. Collection/receipt failures preserve the original exception, wait for that same child to actually exit, then report failure; there is no signal, kill or restart path. Native budgets belong to the reviewed gate/session implementation.

Both before/after complete source maps are retained. Changes to code or non-Git files reject; changes in the three actual Git metadata roots remain visible in the difference list. Allowed prior C++/Verilator wrapper files under `/root/fanzehui` are hashed before/after. System AR is recorded only as an environment dependency and is never stat/read/copied for hashing. These prior wrapper hashes do not assert which tool was selected: actual selection remains in the generated build manifests. Selected environment fields are recorded; arbitrary environment secrets are not printed.

The actual child must exit zero and the gate pass declaration must bind the original first/fresh gzip SHA values with observation-only authority. Full output maps retain original archives, both actual binaries/cache manifests and failure receipts. Controller lifecycle or archive integrity alone does not establish a native pass, retirement, storage proof or source authority.

## Software evidence and remaining operations

17 controller controls pass in 0.15s. RED receipts cover missing implementation, link/Git isolation, actual tiny software child lifecycle, tool scope, no-kill timeout/receipt-failure behavior, gate archive integrity, the real Caliptra lock-artifact LICENSE read set, and bounded internal CVW include links. Controller wiring tests explicitly mock gate admission/tools while using a real tiny software child; real gate admission is covered separately by the 39-control reviewed gate suite.

The prepared launcher is `evidence/cvw-ahb-control-20261017/run-controlled.sh`; it is **not executed**. It sources the established environment, sets source-first imports and nonoptimized Python, checks the finalized controller file SHA before execution, and supplies the exact frozen source/map hashes.

Independent controller source review must precede any remote copy. A future remote preparation must create a new independent base, copy the exact isolated working-tree and self-contained Git bytes without hardlinks, verify the entire map plus host/profile/closure freeze, place finalized controller/launcher receipts separately, and preserve local source overlays. A clean clone alone is insufficient. Root's separate exact native GO remains required after preparation; no current receipt authorizes remote execution.
