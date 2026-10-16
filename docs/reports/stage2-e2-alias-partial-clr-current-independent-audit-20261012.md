# Current partial/repeat CLR independent artifact audit — 2026-10-12

Independent full audit28385 returned0 after generation and fresh workers ended. The prepared CLR audit included the current source-bound sidecar load before its first execution; no setup failure occurred in this audit. No worker, production, cache, saved fact or acceptance assertion changed. No auditor native process ran. Detailed evidence is in [independent-audit.json](../../runs/stage2-e2-register-alias-partial-clr-current-20261012-v1/independent-audit.json).

Ten actual original requests perform B.INTEN0 WRITE/READ, targetA PADOUT seed0xd5aa00ff WRITE/READ, then two fresh selected before-READ→PADOUTCLR0x80000000→after-READ triplets. Actual values are0xd5aa00ff→0x55aa00ff→0x55aa00ff. Each bracket computes actual old & (~actual mask & 0xffffffff) and preserves all0x7fffffff unselected bits. Second before and both after accesses and private result commits map exactly to their designated new case delivery/access/source refs; first after is not substituted for second before in this experiment. The production generic rule still permits legitimate shared adjacent actual READ boundaries; that rule was not changed or described as rejecting valid shared evidence.

Verified totals:21451full events;16confirmed ordinary associations/48full APB projections (ten selected30projections plus six startup18projections);six actual private issued RAM results;ten historical/current behavior certificates (six READ,two ordinary WRITE/READ and two source-bound alias-readback). All ten current-source original request/program/actual-context recompilations match. Both before/after actual result commitments have exact digest/bytes/CPU transaction lineage. Full ordinary/sealed access and certificate projections match the actual unique journal and raw/base/receipt/acceptance/delivery refs.

The production identity verifier and trusted closed selector accepted nine authenticated artifacts;282current source pins and closures45/271/21/271 were rehashed. Exact plan and full semantic trace digest, all sampled command seals, source-bound alias relations, complete actual CPU input/CPU+A+B IRQ projections, current native cache identity/input/binary bytes and fresh semantic/count/whole-wrapper/preflight comparisons pass. Pulse/pending policy snapshots remain diagnostics, not independent functional or quietness rules. Actual low8seed output is retained; IRQ/MIE/input events were not forced or removed. Saved context is comparison data only, not restored authority.

Identity SHA256: `4008d40c0d9e6d9e401be4089b3443f84ea5107cee50ee68281af708911c8aa9`.

Plan SHA256: `1cd88727458621db9ecc66db659686acfcc4d81831a40c88c8f96f5019f5e084`.

Trace semantic SHA256: `9dc75242896642072491e4b9ba8e8b3be831b13077cec4d88ffcc576322484a6`.

Audit script SHA256: `e7f32d9687ef7347a9a9682e07c201339fadf17c0f05e355ff838d7f1a777e4e`.

fresh_cli:complete,139.661912332s,peak2120609792 <limit3459932160bytes,workers1,dut_finding=false.

generation:complete,143.685610874s,peak2345062400 <limit3428487168bytes,workers1,dut_finding=false.

Both generation/fresh retain the original separate180-second single-worker budgets, with all ten requests. Current cache input counts are CPU351/GPIO282each. Fresh fulltrace is not separately persisted; saved original trace and production fresh semantic/count/full-state comparisons are the available evidence.

No scoped artifact mismatch was found . This qualifies the current-source selected high-bit CLR and its actual repeated write/readback only. It does not grant arbitrary masks/values, reset defaults, internal storage/version/prerequisite authority, output/IRQ/function, full E1/E2 or Stage2 completion.
