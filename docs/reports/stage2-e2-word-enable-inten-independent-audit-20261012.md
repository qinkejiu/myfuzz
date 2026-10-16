# Current word GPIOEN/INTEN independent artifact audit — 2026-10-12

Independent full audit process99853 returned0 after both native workers ended. No auditor RTL/native process, production change, worker/cache change or assertion relaxation occurred. Complete results are recorded in [independent-audit.json](../../runs/stage2-e2-register-word-enable-inten-20261012-v1/independent-audit.json).

Six original requests perform real CPU B.INTEN WRITE0→READ into RAM0x10004, A.GPIOEN WRITE0x80000000→READ into0x10008, and A.INTEN WRITE0x80000000→READ into0x1000c. These use SW/LW fullword accesses, with no RMW and no host reset/value oracle. Current source compilation matches each complete saved program, original request and actual admission context. Actual APB readback equals the preceding actual write, issued RAM commit bytes match that actual read, The rule uses actual APB/CPU/RAM values; no DIR/OUT export is substituted as a GPIOEN/INTEN value oracle.

Verified evidence contains13905 full events,12 confirmed ordinary associations and36 full APB projections (six selected accesses/18selected projections plus six startup accesses/18projections), three private issued RAM results, and six historical/current behavior certificates:three ordinary write/readback and three read-result. The actual current source-bound profile/sidecar permissions are full32 rw/none for the selected words. No snapshot grants storage, version dependency, prerequisite or functional completion.

The production identity verifier and closed trusted selector accepted the nine-artifact bundle.282 current pins and enabled closures45/271/21/271 were byte-checked. The audit verified plan hash and complete trace semantic hash, unique actual journal, exact full association projection, acceptance/delivery/receipt/raw/base references, command-sample seals, observed-access/certificate projections, actual commit digest/bytes/CPU lineage and full fresh semantic/count/wrapper/preflight equality. Saved compilation context is comparison only, not restored authority.

All commanded CPU input and CPU/A/B physical IRQ projections and the complete IRQ event array were rebuilt from the actual full trace. B.INTEN0 is supported by an actual selected WRITE/READ, not a forced host IRQ input or MIE assumption. Terminal pending/pulse policy is retained only as diagnostic state; it is not independently reconstructed as a separate functional rule. No IRQ isolation or functionality certificate is inferred.

Each native cache identity equals its authenticated actual Session identity. Every frozen input byte hash and each own native binary digest was checked (CPU351 inputs,GPIO A/B282 each). Exact binary paths/hashes and resource receipts are in the audit JSON.

Identity SHA256: `932be8f1bf78ab518770c9014308eedf5927fcaf9b7f102d9509177866fc44ba`.

Plan SHA256: `2376020b169996ffb1ddc7653445f8fb6cada8afba32953cd9cd48c05a979ee8`.

Trace semantic SHA256: `2e87bdd4b083dd761b01db17f599d6e32c47b63d45e80b137ae8bccd82dcf160`.

Audit script SHA256: `a6776dc0b3ad0a63afca77e0ccf63913b53644780395e4d59d313b0d19016bae`.

fresh_cli:complete,100.399611308s,peak1573228544 <limit3344789504bytes,workers1,dut_finding=false.

generation:complete,116.197953392s,peak1715634176 <limit3350388736bytes,workers1,dut_finding=false.

Generation and fresh each have their own180-second budget. Fresh fulltrace is not separately persisted; the auditor checks the saved full original trace and production fresh semantic/count/full-state comparisons.

No scoped mismatch was found. This is current-source qualification for three observed word WRITE/READ pairs , not all word values, byte/halfword access, GPIO sampling/interrupt functionality, complete permission/effect/reset matrix, whole L2, RFuzz/BFM, functional completion or full E1/E2/Stage2 acceptance. Prior64 narrow-field single-value qualifications remain distinct.
