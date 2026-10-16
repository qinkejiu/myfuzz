# First INTTYPE_HIGH selected-field independent artifact audit — 2026-10-12

The scoped first HIGH field gate passed independent read-only audit. Auditor process45969 returned0 after generation and fresh CLI workers had both terminated; the auditor started no native process. The next HIGH pin18–21 audit remains prepared and unexecuted. No worker, production, cache, or saved evidence was modified to satisfy an assertion.

The original eight requests are four explicit RMW and four subsequent READ operations on targetA INTTYPE_HIGH pin16/pin17/pin30/pin31, with one legal relative value point each:1/2/3/2. Actual masks are0x3/0xc/0x30000000/0xc0000000 at lsb0/2/28/30. All eight current-source compilations match the saved original request/program/actual context exactly. RMW fragments are36bytes and actual writes equal `(actual LW word & ~busmask) | shifted_value`; all unselected bits are preserved. READ RAM results are field-relative zero-extended values computed from the actual APB read word, not a reset-default assumption.

Verified totals are18218 full events,18 confirmed ordinary associations (six startup plus twelve selected),54 full APB projections (18startup+36selected),four actual issued RAM result commits, and eight historical/current certificates:four `ordinary_register_rmw_readback.v1` plus four `ordinary_register_read_result.v1`. These are observations of CPU register readback consistency; no storage-version, prerequisite, functional, reset-default or full-level grant follows.

The independent production identity verifier and closed trusted selector accepted the authenticated nine-artifact bundle. The audit rechecked282 current source pins and all enabled closures (online45,ordinary271,register21,verifier271); plan hash, trace semantic hash and unique journal identity; all acceptance/delivery/target receipt and raw/base references; exact command sample seal and observed-access projections; issued RAM commit digest/bytes/transaction lineage; saved full ordinary/verifier wrapper and actual fresh semantic/count/state/preflight comparisons. Saved input contexts were used only for exact recompilation comparison, never installed as authority.

IRQ runtime names derive from authenticated CPU/A/B physical exports plus the code-owned CPU profile IRQ endpoint/role. All CPU input commands,2766 actual physical IRQ sample projections and the complete IRQ event projection (zero in this captured run) reconstruct exactly from the full trace. The terminal policy snapshot is retained only as diagnostic data; it was not independently rebuilt as a pulse state machine and is not used to certify quietness or functional IRQ behavior.

Each of the three current native build identities equals the authenticated actual Session identity. Every frozen input byte hash (CPU351,GPIO A282,GPIO B282) and each own native binary digest matches its own manifest. Actual paths, binary/build-identity hashes, source counts and resource receipts are recorded in [independent-audit.json](../../runs/stage2-e2-register-field-inttype-high-20261012-v1/independent-audit.json).

- Identity SHA256: `09fb6bc107ba6eb27d0dbca92e25f12f1169f8de0e18bf107a32fe435d6e9337`
- Plan SHA256: `630e52b0b064e581c28d0e60adbd09a712871eff400800d0beb24a5981bc1a4f`
- Trace semantic SHA256: `245790b508f25245a9c0170049cc153789cf38505c087f85c90e5b3d4573b671`
- Audit script SHA256: `e4b0c22e9311d11a15be950d74625d30fad7c94951ab13152a8c1901bb4c1d65`
- Generation:complete,132.307083692s,peak2046111744bytes <limit3096285184,workers1.
- Fresh CLI:complete,116.242263342s,peak1848770560bytes <limit3092434944,workers1.

Both actual resource receipts have `dut_finding=false`; their180-second budgets are separate, not a combined-budget claim. Fresh fulltrace is not separately persisted, so the saved original full trace is independently verified and the production fresh CLI semantic/count/full wrappers are compared exactly.

No concrete scoped artifact mismatch was found. Only four selected fields with one tested value each are accepted here. All possible field values, remaining fields/banks, complete permission/width/mask/effect and reset matrix, full L2, functional/RFuzz/BFM and whole Stage2 completion remain open. Current frozen production Session is f7da03f4…c4bafa0, integration bfbb72a8…9510bf, verifier0375ed3f…a0470 and build06334fed…7056c; full byte pins are in the authenticated manifest and independent JSON.

The actual source-bound HIGH register offset is0x20. Pin31 relative value2 shifts into bit31, and the actual RMW write/read result confirms unsigned mask handling and field-relative result2 without granting behavior for all four possible values. Actual rendered GPIO source supports the selected pin31; no reduced-PAD_NUM declaration is used as authority.
