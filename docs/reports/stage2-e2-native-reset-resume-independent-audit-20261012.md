# Native recorded reset/resume independent artifact audit — 2026-10-12

Both scoped schema18 gates passed independent read-only artifact verification. Warm audit process50618 and cold audit process70286 each returned0; they ran serially after all native generation/fresh processes ended. The auditor started no native process and changed no production, worker, cache, or historical artifact.

The two runs each submit original `gpio_a / gpio.bus / INTEN.value` READ requests on either side of an actual recorded reset/resume. These establish observed CPU register-read/result consistency and authenticated fresh replay of that workflow. They do not establish a reset-default oracle or internal storage version dependency.

| Evidence | warm_all | cold_all |
|---|---:|---:|
| Cases | 2 | 2 |
| Full trace events | 9391 | 9114 |
| Confirmed ordinary associations | 15 | 14 |
| Full APB request/accept/response projections | 45 | 42 |
| All authenticated RAM commits | 3 | 2 |
| Historical certificates | 2 | 2 |
| Current certificates | 1 | 1 |
| Recorded resume component steps | 183 | 159 |
| Current source pins | 282 | 282 |
| Authenticated artifacts | 9 | 9 |

Warm memory generation remains0 across reset; cold advances0→1. All three actual component reset epochs advance0→1. Warm records61 three-component schedules (183steps), reaches the next missing instruction address69648, and retains an unselected actual reexecution of the pre-reset READ, accounting for its third RAM commit. Cold records53 schedules (159steps) and returns to first declared instruction address69632. The selected result proofs remain exactly two per run; an extra unselected access is not promoted to a selected certificate.

Reset and resume snapshots retain the existing historical certificate but have no current certificates. Final snapshots contain two historical READ certificates and only the post-reset certificate as current. Each rule is `ordinary_register_read_result.v1` with scope `observed_cpu_register_readback_consistency`; saved records are comparison data, not restored authority.

The audit accepted the production run-identity verifier and closed trusted register selector; validated all nine artifact hashes; recompiled both original requests against current source-bound profile/sidecar and saved actual context for exact comparison; verified plan hash, full trace semantic hash, unique journal IDs, complete ordinary-record projection, actual acceptance/delivery/receipt and raw/base references, sample-seal projection, result commit digest/bytes/source transaction and certificate projections. The recorded reset row is exact schema18 with `after_cases=1`, actual policy and all recorded schedules. The actual reset barrier and saved reset/resume event arrays occur unchanged in the full journal.

IRQ diagnostics were reconstructed completely from the full trace: all commanded CPU input arrays, all CPU/B physical samples, and all IRQ event rows compare exactly. Runtime names derive from authenticated artifact exports and the code-owned CPU profile IRQ endpoint/role. Warm has888 physical samples and cold856; both have0 IRQ event rows in this captured experiment. No quiet-IRQ condition, MIE disabling, or reset-default value was assumed.

Current manifest source closures contain45 online,271 ordinary-access,21 register-program, and271 verifier source entries. Each byte hash was rechecked. Each run independently verifies its own actual cache build identity against the authenticated Session manifest, all frozen input bytes (GPIO A282, CPU351, GPIO B282), and each native binary against its own cache manifest. Cross-directory binary equality is not required; compiled path differences do not constitute shared runtime authority.

## warm evidence identifiers

- Identity SHA256: `afec5d21838c2756f2aceccb415b56f096eaad886ca12413494582bbd74a9766`
- Plan SHA256: `452eb8577e6922f010e89e5744e04b49015bf3dec15f464e693248c00291451d`
- Trace semantic SHA256: `b90e6895f2f036ec03cde3a059231a94c72b1b21a79270dbfa410b86beb0b5b2`
- Selected RAM commit event IDs: `[3018, 7912]`
- Full details and actual binary paths/hashes: [independent-audit.json](../../runs/stage2-e2-register-reset-resume-warm-20261012-v1/independent-audit.json)

- fresh_cli: complete, 126.435815431s, peak 1040527360 bytes < 3105226752 bytes, workers1.
- generation: complete, 144.043208753s, peak 1112051712 bytes < 3103797248 bytes, workers1.

## cold evidence identifiers

- Identity SHA256: `7de9ff4b411fe6a0bf78ae2d671c657a9b9f99135e6db91f8bfc92afaf99c68f`
- Plan SHA256: `77545c7956415d044af7aec8cbb37fd69b52d365e68c794faf9e684a5388653d`
- Trace semantic SHA256: `34f235e3c711c79ae54378af886baa130e1c613821edd77f9e4062ba716a3b1e`
- Selected RAM commit event IDs: `[3018, 7635]`
- Full details and actual binary paths/hashes: [independent-audit.json](../../runs/stage2-e2-register-reset-resume-cold-20261012-v1/independent-audit.json)

- fresh_cli: complete, 118.051542754s, peak 1041219584 bytes < 3134656512 bytes, workers1.
- generation: complete, 136.892561557s, peak 1119137792 bytes < 3142094848 bytes, workers1.

The generation and fresh CLI budgets are separate180-second runs, not a combined180-second claim. Both resource receipts are complete, below their actual RSS limits and with `dut_finding=false`. Production fresh CLI reports match the entire semantic trace/count plus ordinary-access state, verifier wrapper, and capability preflight. Fresh fulltrace is not separately persisted, so the auditor verifies the saved full original trace and the production fresh semantic/full-state result rather than an independently saved second trace.

Frozen production identities checked: Session `f7da03f4b74d21e36736fbe50e3891937108c1a78a9d9d52c3a870398c4bafa0`; integration `bfbb72a8bc79e7f37150e125670ceb8dd78ee1fc39497e397a5c15d4809510bf`; verifier `0375ed3ffcd9a4ec012ab8873f5874212d2c9d9dfd0878fcb1b9ab5554ca0470`; build `06334fedf08cacd861806362dc216026af3b426cd80be2ceb10929ff2197056c`. Both independent audit scripts SHA256: `db4fe85001bb00384db6d88b45eef0c179433faf93cd4ef6ebf122afa25bcd24`.

No remaining concrete artifact mismatch was found in this scope. Reset-default certification, storage-version/prerequisite authority, complete L2 permission/width/mask/effect matrix, functional completion, RFuzz/BFM, and whole Stage2 completion remain outside this evidence.
