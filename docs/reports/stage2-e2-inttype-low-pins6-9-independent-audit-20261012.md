# INTTYPE_LOW pins6–9 selected-field independent artifact audit — 2026-10-12

The scoped third field gate passed independent read-only audit. Auditor process55905 returned0 after generation and fresh CLI workers had both terminated; the auditor started no native process. The next pin10–13 audit remains prepared and unexecuted. No worker, production, cache, or saved evidence was modified to satisfy an assertion.

The original eight requests are four explicit RMW and four subsequent READ operations on targetA INTTYPE_LOW pin6/pin7/pin8/pin9, with one legal relative value point each:3/1/2/3. Actual masks are0x3000/0xc000/0x30000/0xc0000 at lsb12/14/16/18. All eight current-source compilations match the saved original request/program/actual context exactly. RMW fragments are36bytes and actual writes equal `(actual LW word & ~busmask) | shifted_value`; all unselected bits are preserved. READ RAM results are field-relative zero-extended values computed from the actual APB read word, not a reset-default assumption.

Verified totals are18227 full events,18 confirmed ordinary associations (six startup plus twelve selected),54 full APB projections (18startup+36selected),four actual issued RAM result commits, and eight historical/current certificates:four `ordinary_register_rmw_readback.v1` plus four `ordinary_register_read_result.v1`. These are observations of CPU register readback consistency; no storage-version, prerequisite, functional, reset-default or full-level grant follows.

The independent production identity verifier and closed trusted selector accepted the authenticated nine-artifact bundle. The audit rechecked282 current source pins and all enabled closures (online45,ordinary271,register21,verifier271); plan hash, trace semantic hash and unique journal identity; all acceptance/delivery/target receipt and raw/base references; exact command sample seal and observed-access projections; issued RAM commit digest/bytes/transaction lineage; saved full ordinary/verifier wrapper and actual fresh semantic/count/state/preflight comparisons. Saved input contexts were used only for exact recompilation comparison, never installed as authority.

IRQ runtime names derive from authenticated CPU/A/B physical exports plus the code-owned CPU profile IRQ endpoint/role. All CPU input commands,2766 actual physical IRQ sample projections and the complete IRQ event projection (zero in this captured run) reconstruct exactly from the full trace. The terminal policy snapshot is retained only as diagnostic data; it was not independently rebuilt as a pulse state machine and is not used to certify quietness or functional IRQ behavior.

Each of the three current native build identities equals the authenticated actual Session identity. Every frozen input byte hash (CPU351,GPIO A282,GPIO B282) and each own native binary digest matches its own manifest. Actual paths, binary/build-identity hashes, source counts and resource receipts are recorded in [independent-audit.json](../../runs/stage2-e2-register-field-inttype-low-pins6-9-20261012-v1/independent-audit.json).

- Identity SHA256: `dc199c25d57bb5709bb2f701cdcf35e49c76ccea092ae32906dedb9a49782e69`
- Plan SHA256: `92bca021d0e5c7d6f062160230c0ec68f1e4019f0d6906e07d31f1511465761a`
- Trace semantic SHA256: `1aef8e3bf66496602c69ea66ecab9e41a61306b00c5b3f66f345a83e1ef59186`
- Audit script SHA256: `9046bee4334abd09581081e041c9b638bdc61a8673fccc492091995e9bc489c9`
- Generation:complete,132.385701888s,peak2046533632bytes <limit3117260800,workers1.
- Fresh CLI:complete,118.394755874s,peak1850974208bytes <limit3117637632,workers1.

Both actual resource receipts have `dut_finding=false`; their180-second budgets are separate, not a combined-budget claim. Fresh fulltrace is not separately persisted, so the saved original full trace is independently verified and the production fresh CLI semantic/count/full wrappers are compared exactly.

No concrete scoped artifact mismatch was found. Only four selected fields with one tested value each are accepted here. All possible field values, remaining fields/banks, complete permission/width/mask/effect and reset matrix, full L2, functional/RFuzz/BFM and whole Stage2 completion remain open. Current frozen production Session is f7da03f4…c4bafa0, integration bfbb72a8…9510bf, verifier0375ed3f…a0470 and build06334fed…7056c; full byte pins are in the authenticated manifest and independent JSON.
