# Current word DIR/OUT independent artifact audit — 2026-10-12

Independent full audit process42062 returned0 after both native workers ended. No auditor RTL/native process, production change, worker/cache change or assertion relaxation occurred. Complete results are recorded in [independent-audit.json](../../runs/stage2-e2-register-word-dir-out-20261012-v1/independent-audit.json).

Six original requests perform real CPU B.INTEN WRITE0→READ into RAM0x10004, A.PADDIR WRITE0x80000000→READ into0x10008, and A.PADOUT WRITE0x80000000→READ into0x1000c. These use SW/LW fullword accesses, with no RMW and no host reset/value oracle. Current source compilation matches each complete saved program, original request and actual admission context. Actual APB readback equals the preceding actual write, issued RAM commit bytes match that actual read, and selected A DIR/OUT output observations contain the same values. Physical-pad drive behavior is not certified by this port-value observation.

Verified evidence contains13907 full events,12 confirmed ordinary associations and36 full APB projections (six selected accesses/18selected projections plus six startup accesses/18projections), three private issued RAM results, and six historical/current behavior certificates:three ordinary write/readback and three read-result. The actual current source-bound profile/sidecar permissions are full32 rw/none for the selected words. No snapshot grants storage, version dependency, prerequisite or functional completion.

The production identity verifier and closed trusted selector accepted the nine-artifact bundle.282 current pins and enabled closures45/271/21/271 were byte-checked. The audit verified plan hash and complete trace semantic hash, unique actual journal, exact full association projection, acceptance/delivery/receipt/raw/base references, command-sample seals, observed-access/certificate projections, actual commit digest/bytes/CPU lineage and full fresh semantic/count/wrapper/preflight equality. Saved compilation context is comparison only, not restored authority.

All commanded CPU input and CPU/A/B physical IRQ projections and the complete IRQ event array were rebuilt from the actual full trace. B.INTEN0 is supported by an actual selected WRITE/READ, not a forced host IRQ input or MIE assumption. Terminal pending/pulse policy is retained only as diagnostic state; it is not independently reconstructed as a separate functional rule. No IRQ isolation or functionality certificate is inferred.

Each native cache identity equals its authenticated actual Session identity. Every frozen input byte hash and each own native binary digest was checked (CPU351 inputs,GPIO A/B282 each). Exact binary paths/hashes and resource receipts are in the audit JSON.

Identity SHA256: `89c76c958c9fee3e91acd37ad9a34e18775d89968f71fab41b5edabe76023cd8`.

Plan SHA256: `da98a9aa958ee5aaba9219514aff1cb70c04be8403b0ad13240bac7eb372f368`.

Trace semantic SHA256: `67901c4321c154b0304d97a151905ec6d8da1c684bf6ac98a67ccb52b5150c33`.

Audit script SHA256: `8eaa6732bf4b6e45deb6a820d44080d9bf32c52a3ab5e81d2299c0e9f2808b75`.

fresh_cli:complete,101.759058767s,peak1575030784 <limit3332112384bytes,workers1,dut_finding=false.

generation:complete,119.192237872s,peak1715609600 <limit3334582272bytes,workers1,dut_finding=false.

Generation and fresh each have their own180-second budget. Fresh fulltrace is not separately persisted; the auditor checks the saved full original trace and production fresh semantic/count/full-state comparisons.

No scoped mismatch was found. This is current-source qualification for three observed word WRITE/READ pairs and selected output values, not all word values, byte/halfword access, physical pad behavior, complete permission/effect/reset matrix, whole L2, RFuzz/BFM, functional completion or full E1/E2/Stage2 acceptance. Prior64 narrow-field single-value qualifications remain distinct.
