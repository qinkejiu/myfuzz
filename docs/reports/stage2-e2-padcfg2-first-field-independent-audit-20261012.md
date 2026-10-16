# First PADCFG_2 selected-field independent artifact audit — 2026-10-12

The scoped first PADCFG_2 field gate passed independent read-only audit. Auditor process35340 returned0 after generation and fresh CLI workers had both terminated; the auditor started no native process. The next PADCFG_2 pin18–21 audit remains prepared and unexecuted. No worker, production, cache, or saved evidence was modified to satisfy an assertion.

The original eight requests are four explicit RMW and four subsequent READ operations on targetA PADCFG_2 pin16/pin17/pin22/pin23, with one legal relative value point each:1/5/10/15. Actual masks are0xf/0xf0/0x0f000000/0xf0000000 at lsb0/4/24/28. All eight current-source compilations match the saved original request/program/actual context exactly. RMW fragments are36bytes and actual writes equal `(actual LW word & ~busmask) | shifted_value`; all unselected bits are preserved. READ RAM results are field-relative zero-extended values computed from the actual APB read word, not a reset-default assumption.

Verified totals are18222 full events,18 confirmed ordinary associations (six startup plus twelve selected),54 full APB projections (18startup+36selected),four actual issued RAM result commits, and eight historical/current certificates:four `ordinary_register_rmw_readback.v1` plus four `ordinary_register_read_result.v1`. These are observations of CPU register readback consistency; no storage-version, prerequisite, functional, reset-default or full-level grant follows.

The independent production identity verifier and closed trusted selector accepted the authenticated nine-artifact bundle. The audit rechecked282 current source pins and all enabled closures (online45,ordinary271,register21,verifier271); plan hash, trace semantic hash and unique journal identity; all acceptance/delivery/target receipt and raw/base references; exact command sample seal and observed-access projections; issued RAM commit digest/bytes/transaction lineage; saved full ordinary/verifier wrapper and actual fresh semantic/count/state/preflight comparisons. Saved input contexts were used only for exact recompilation comparison, never installed as authority.

IRQ runtime names derive from authenticated CPU/A/B physical exports plus the code-owned CPU profile IRQ endpoint/role. All CPU input commands,2766 actual physical IRQ sample projections and the complete IRQ event projection (zero in this captured run) reconstruct exactly from the full trace. The terminal policy snapshot is retained only as diagnostic data; it was not independently rebuilt as a pulse state machine and is not used to certify quietness or functional IRQ behavior.

Each of the three current native build identities equals the authenticated actual Session identity. Every frozen input byte hash (CPU351,GPIO A282,GPIO B282) and each own native binary digest matches its own manifest. Actual paths, binary/build-identity hashes, source counts and resource receipts are recorded in [independent-audit.json](../../runs/stage2-e2-register-field-padcfg2-20261012-v1/independent-audit.json).

- Identity SHA256: `6d3f9c74e46d4610efc2797a1a9be59a031551f492da5fc41fc6a40011e14eb5`
- Plan SHA256: `27cac1ed18da57445124420b72cff993eeeb317001fcde52537b15ac14cd9596`
- Trace semantic SHA256: `bd5c67e2b496e97f10d5a6332308ab2dff7d8fca480cae6b8402541b99ca5b4a`
- Audit script SHA256: `29e205fe3c445ebfae14362de2dd0d08337cf8524ae82cb712009239a504f389`
- Generation:complete,132.999130042s,peak2046648320bytes <limit3301568512,workers1.
- Fresh CLI:complete,119.251310228s,peak1850802176bytes <limit3239477248,workers1.

Both actual resource receipts have `dut_finding=false`; their180-second budgets are separate, not a combined-budget claim. Fresh fulltrace is not separately persisted, so the saved original full trace is independently verified and the production fresh CLI semantic/count/full wrappers are compared exactly.

No concrete scoped artifact mismatch was found. Only four selected fields with one tested value each are accepted here. All possible field values, remaining fields/banks, complete permission/width/mask/effect and reset matrix, full L2, functional/RFuzz/BFM and whole Stage2 completion remain open. Current frozen production Session is f7da03f4…c4bafa0, integration bfbb72a8…9510bf, verifier0375ed3f…a0470 and build06334fed…7056c; full byte pins are in the authenticated manifest and independent JSON.

These are four-bit PADCFG fields with relative read/write masks15. Their observed register-value consistency does not certify physical pad configuration behavior. Only the four selected values are tested, not all sixteen encodings per field.
