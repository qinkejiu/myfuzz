# CPU AHB observation design and actual-source audit

2026-10-17, proposed for root interface approval. No implementation or new native execution. Applies the brainstorming design workflow; source facts and historical raw evidence were inspected before selecting the design.

## Corrected historical evidence boundary

Root audit 7e898ef correctly identified pipeline semantics and the service hook. Its phrase “physical exports” must be narrowed: the AHB adapted endpoint is not in ordinary physical exports. Current runtime_renderer `_shape` resolves all 13 actual ABI wires, but the AHB branch never exports them as protocol taps. Only unadapted HCLK/HREADY/HRESETn are exported. HREADY output is explicitly not the declared hready input HREADYEXT.

Read only existing `/root/fanzehui/cvw-caliptra-chain-20261017` evidence. `runs/cvw-caliptra-chain-20261017/{first,fresh}.json` each have 1248 CPU samples (ticks1..1248), 261 accepted backend requests, 51 backend writes, 261 backend response consumptions, zero sampled backend errors and pending0. Their complete documents differ only in executions. Original SHA256 first915bac7a714e9a1993dfcbe4ffb4402e687f33b67d7c26ce3d1025888284df19, fresh575ce1567aacfe2808bb4f11812a13bf7d2f9ee3432ab0f2b742c99cfc51422f. Each CPU pre/post physical dictionary contains only three bits. Cached CPU artifact aadf4a... has those same three exports and no CPU trace. No address/data/control/HRESP roles can be recovered from that raw record. Its first sample already has an accepted backend request, so startup AHB address phase is not observable either.

These are old generated native backend-service evidence, not a new observer pass and not AHB physical coverage. The target's errors are zero here; CPU error behavior is unknown. Original bytes are archived losslessly as gzip alongside `audit-receipt.json` in docs/reports/evidence/cvw-ahb-source-audit-20261017. SHA records pin original and gzip separately. No model, compiler, build, elaboration, remote writer or heavy lock was used.

## Approaches

1. Recommended: independent CPU AHB observer plus actual AHB wire taps and a default no-op verified-edge service hook. It captures the physical pipeline without changing IP normalizer semantics.
2. Backend-only event projection is smaller but loses address/data phase timing, control, HRESP and simultaneous pipeline behavior; it does not meet the requirement.
3. Reuse IP AHB normalizer would falsely reject old-completion/new-address overlap and lose the new address; reject this option.

## Minimal source interfaces

- New `scenario/ahb_cpu_events.py`: code-owned versioned shape and observer, no CPU-name branching. Exact roles haddr34, hwdata/hrdata32, hwstrb4, htrans2, hsize3, hburst3, hprot4, hwrite/hmastlock/hsel/hready/hresp1. Identity includes shape, observer version, complete trace mapping and budgets. All fields are raw role values; no guessed instruction/data identity.
- AHB-only renderer addition: after `_shape`, export each actual bound wire as a protocol tap with endpoint/role/width/source_wire facts, following existing OBI taps machinery. The driver already records optional `protocol_taps` in both phases and sizes its bounded snapshot. Add CPU trace declaration with `boundary=cpu_physical_abi`, exact13 roles and actual primary clock; preserve original physical_exports. No invented wire names or target-side HREADY substitution.
- Generic `GeneratedNativeMemorySession._observe_verified_memory_edge(receipt)` default no-op, called after status/new_ticks/control echo/sample-pre binding validation and last_samples capture, before pending response mutation or memory/router service. This changes no other protocol behavior. AHB overrides only this hook.
- AHB step wrapper checks permanent observer state before boot logic/command, catches every ordinary Exception across command/validation/observer/service/output projection, preserves available raw receipt or untrusted diagnostic, records possible_effects, closes native and poisons before retry. Command parsing failure may have clocked without trusted projection and must remain unknown. No broad change to other NativeMemorySession error policy is required.
- Reset immediately cancels every old-scope pending observation before transport reset and retains old raw/events. Runtime event list is never replaced. Begin-case resets measurement scope state, not global budgets or historical rows. Source scope includes issued execution, testcase, reset epoch, endpoint and component.

## Measurement state machine

Only validated pre values determine an edge. On each edge: (1) if a prior address is pending and pre hready is1, complete that data phase using actual HRDATA/HRESP and its associated write payload; (2) independently if pre hready&&hsel&&htrans[1], admit the new address/control on this same edge. An idle ready level with no pending address is not a response. IDLE/BUSY do not admit addresses. Post retains the measured post image and checks applicable continuity; it never creates another transfer.

A write's address edge does not contain its write data. The next pre image is the earliest write-data phase; capture actual HWDATA/HWSTRB there, retain across wait edges, and correlate through completion. Read data is sampled at completion, not frozen during arbitrary wait cycles. Address/control offered while hready low are not accepted; preserve and check applicable pending offer stability without mechanically applying AXI VALID/READY rules. Response-error control exceptions must be represented explicitly rather than claiming every change during an ERROR sequence is a violation. Track observations/diagnostics for stalled HRESP and completion HRESP; HRESP1 means an observed bus error completion, not automatically a protocol bug. Full two-cycle ERROR compliance is outside the currently implemented target contract and must not be claimed.

Retain htrans/hsize/hburst/hprot/hmastlock/hwstrb exactly, including zero strobes. The target transports/ignores several of these semantics and MAX_WAIT_CYCLES is unused by RTL. Do not manufacture burst transaction completion, lock execution, size legality, instruction classification or a 16-cycle native timeout guarantee from profile declarations. This increment reports beats and pipeline relationships; future burst/lock conformance is explicit follow-up.

## Budgets and evidence

One pending data phase, one offered address wait observation and one write payload per stream/scope. Global defaults proposed: 100000 edges, 64MiB serialized raw stopping threshold, 1000000 events, 256 scopes. Version/identity pin exact limits; custom lower limits allowed for software controls. First offending edge is retained, so byte budget is a stopping threshold rather than strict allocation cap. Exhaustion is terminal; new reset/scope cannot renew budgets. Diagnostic events preserve raw refs and possible effects with trusted_projection false for unvalidated shape/tick/budget entry. Accepted/completed/pending/stalled/error/reset counters remain explicit. No source authority, runtime acceptance, semantic acceptance or retirement; observation_only throughout.

Existing Runner imports the stable runtime_events list once; add targeted controls for repeat drain0, independent sources, scope mismatch, reset cancellation and full fresh prefix with only typed declared execution normalization. Raw references identify exact sample/tick/pre or post and correlation links across address/write-data/completion.

## RED to GREEN validation after approval

Software first: exact ABI mapping rejects missing/duplicate/wrong direction/width/endpoint roles; renderer source tests inspect all13 assign connections and driver taps. Historical samples explicitly fail missing-shape admission, remain preserved, and cannot pass physical replay. Constructed software traces then cover old-read/write-completion+new address, address/data separation, stalls, true34-bit address, strobe0/partial, HRESP completion, response-error exceptions, IDLE/BUSY, post non-double-counting, malformed receipts/shapes, all Exception failure paths, before-command retry refusal, reset, multiple sources and permanent global budget exhaustion. Run targeted unchanged generic/native session tests to confirm no-op hook compatibility. No new native during this phase.

A separately scheduled new frozen generated native gate is required after software/review: actual taps raw+full receipts+observer replay+Runner once-only+fresh full prefix+PID close and complete source/build identity. The old Caliptra chain can motivate the program but cannot substitute for new event native evidence.
