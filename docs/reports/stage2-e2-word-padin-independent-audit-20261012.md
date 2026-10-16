# Current PADIN word independent artifact audit — 2026-10-12

Independent full audit process75237 returned0 after both generation and fresh workers terminated. No auditor native process, production/worker/cache change or assertion relaxation occurred. Detailed proof hashes and actual cache binary paths are in [independent-audit.json](../../runs/stage2-e2-register-word-padin-20261012-v1/independent-audit.json).

Four original requests are actual CPU B.INTEN WRITE0→READ into RAM0x10004, A.PADIN READ into0x10008, and B.PADIN READ into0x1000c. Current source-bound PADIN is full32 RO,offset8,readmaskffffffff/write0/none. All four fresh current-source compilations exactly match saved original requests/programs/actual admission contexts. PADIN RAM bytes are compared with the actual APB/CPU read value; no host instantaneous pad value, synchronizer state, reset declaration or forced IRQ/MIE input is installed as an oracle.

Verified totals:10129full events;10confirmed ordinary associations/30full APB projections (four selected12projections plus six startup18projections);three actual issued RAM results;four historical/current behavior certificates (one ordinary write/readback and three read-result). These prove observed CPU register readback/result consistency, not physical-input sampling causality or reset defaults.

The production identity verifier and closed trusted selector accepted all nine authenticated artifacts.282 current source pins and closures45/271/21/271 were byte-checked; exact plan hash/full trace semantic hash and unique journal IDs, actual acceptance/delivery/target receipt/raw/base refs, command sample seals, completed access/certificate projections, actual RAM commit digest/bytes/source-transaction lineage, and full fresh semantic/count/ordinary/verifier/preflight comparisons all passed. Saved context is only recompilation comparison data, not live authority.

Complete commanded CPU inputs and CPU/A/B physical IRQ/event arrays reconstruct exactly from the saved full trace. Terminal pulse/pending policy remains diagnostic only, not an independently reconstructed functional rule. The initial B.INTEN0pair is actual CPU data, not a magic quietness condition. Each actual cache build identity matches the authenticated Session; all frozen input bytes and native binary hashes match each own manifest (CPU351/GPIO282each).

Identity SHA256: `7391bd31ec5a149e4d04ae90b7ebe451a9dc59030b35d3807eeb7f7cc3360638`.

Plan SHA256: `d53e6f3a0444c23c607e7ba5a326c1469887d622038786f7929041d003890ad5`.

Trace semantic SHA256: `77ac9f1d2ec93ae92b3e5a0a2c24db2b881bf4f4ba3ffdd878fcc50de0702baa`.

Audit script SHA256: `30143fe197543086acecbaff62c09961e82ebc82f4d8a1ee38e1d0cb3bd67ae7`.

fresh_cli:complete,87.219112558s,peak1302310912 <limit3359363072bytes,workers1,dut_finding=false.

generation:complete,103.988880602s,peak1414696960 <limit3361574912bytes,workers1,dut_finding=false.

Separate180-second generation/fresh budgets were respected. Fresh fulltrace is not separately persisted; the saved original trace and production fresh semantic/count/full-state comparisons are the available audit evidence.

No scoped mismatch was found. PADIN evidence does not grant sampling/synchronizer behavior, reset-default, storage/version/prerequisite authority, full permission/width/effect/reset matrix, L2/function, RFuzz/BFM or whole E1/E2/Stage2 completion.
