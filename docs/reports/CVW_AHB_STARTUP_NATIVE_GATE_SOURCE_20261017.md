# CVW → Caliptra AHB startup gate: source-only implementation

This increment prepares a future generated native gate. **No new DUT build, elaboration, model, remote snapshot or native run was performed.** The old historical CPU samples expose only three physical pins and remain unsuitable as new thirteen-role CPU AHB evidence.

## Fixed experiment

The gate reuses `make_cvw_caliptra_chain`, its original 1024-byte static program, memory seed 17, and 20000 CPU-step upper bound. It stops on the original real `memory_write` to `RESULT+64` with backend pending responses zero; final RAM flag and the two SHA256 digests are checked. Both genuine session classes are registered in a strict ScenarioManifest and ScenarioBatchRecorder. Only `advance(('cpu',))` is submitted. Caliptra clocks come exclusively from real router register accesses; no roundrobin target STEP, source mutation, probe, quiesce or extra CPU cycle is introduced.

Runner begins independent sessions in its existing order. The CPU's generated startup measurement captures reset/release without service acceptance; no router call occurs before ordinary session stepping. Reset/READY timing is owned by the previously reviewed startup implementation, not changed by this script.

## Original evidence and crosslinks

Passive instance wrappers preserve actual session classes and forward original input, return value and exception. They retain each actual API operation/fields and parsed DriverReceipt, including zero-clock startup pages. These are API-level command/receipt archives; they do not claim to be a raw stdout/ACK transcript. Original startup and CMD tick namespaces remain unchanged.

Before Runner drains lists in place, the wrapper saves the original observer/service/router rows. Each original service/router row has a separate step index, local tick and current CPU receipt index. Complete original row sequences are compared with Runner imports, and every context must point to the same real command edge. A repeated observer index with changed payload rejects. The initial flag predicate reads the retained original service rows, preserving the original accumulated-event semantics.

The gate checks all startup pages before the first command, requires at least that command, and reprojects the complete startup→CMD prefix with the actual ABI role map. Entire observer events, counts and pending state must match offline. Actual backend MMIO requests and read responses must bind to real router deliveries. Target ACCESS receipts bind one-for-one to deliveries and account for every target tick; extra target STEP operations reject. A separate bounded physical reconstruction authenticates all ten target AHB trace roles against structural ABI and backend declarations, accepts only measured PRE address phases, completes the prior data phase before a same-edge new address, checks address and write-data stalls, and compares every completed physical transfer with router deliveries. Missing/extra/pending transfers and physical error completions reject this directed success gate. Target reset itself is not claimed as measured; only CPU startup has the new reset-to-command capture.

Both processes must provide actual Popen handles, issued execution nonces, distinct fresh PIDs, READY and successful close/reap status. Actual binary SHA, raw cache manifest bytes/SHA, build identity and executable argv are crosslinked. Both full artifacts and Runner source identities are retained. Failures preserve per-run receipts/partial rows, terminate the attempted gate, and prohibit later captured commands. An outer failure receipt records failures before a per-run archive could be issued.

## Comparison and limits

First/fresh compares entire original receipt streams, observer streams, Runner streams, program, source/artifact/build identities, outputs, router/service rows and contexts. Only schema-declared observer scope execution IDs, embedded startup DriverReceipt execution IDs, and the two component DriverReceipt execution fields are normalized, after exact binding to that run's issued nonce. Unknown UUIDs reject; arbitrary payload strings are preserved.

Only the measured reset-to-command prefix is certified as observed. A final outstanding physical address remains explicitly `partial`, even when backend pending is zero. No bus-drain, retirement, CPU semantic acceptance, reset authority or source authority is granted.

Bounds include 20000 submitted CPU advances, existing startup max2048 edges/8MiB capture, existing observer budgets, a 128MiB receipt archive per session, 740000 per-component cycles/760000 scheduler cycles, and 600000ms wall budget. Existing parser/page bounds remain in force. The canonical heavy lock is acquired nonblocking; busy means refusal, never queueing. Native paths must be confined to `/root/fanzehui`, source must match the executing independent snapshot, and output must be new and separate.

## Software evidence

`tests/local_harness/test_cvw_ahb_gate.py` contains 39 controls; the final focused run passed all 39 in 14.40s. These include real CPU startup session methods with genuinely parsed wire RESULT fixtures, actual dual-session constructors/strict manifest reconstruction with saved ABI facts and git-only subprocess guards, passive capture/drain/exception controls, binary/lifecycle tampering, typed whole-prefix comparison, source-only default CLI isolation, physical target HADDR/HWDATA/HRDATA/HRESP tampering, stalls and extra-transfer/ABI controls. Comparator unit models explicitly bypass native admission only to test comparison; they cannot establish a native pass.

The historical saved chain is used solely for existing backend/router/digest payload checks and a corrupt read-response negative control. It is not substituted for new startup or thirteen-role measurements.

RED/GREEN receipts, combined output and exact source-freeze hashes are under `evidence/cvw-ahb-gate-20261017/`. The freeze hashes the actual working tree host closure. Later shared-source edits invalidate that freeze and require a new reviewed snapshot receipt before remote preparation.

## Remaining gate

Independent source review, a separately authorized independent remote source snapshot, and root's exact native GO remain required. The eventual first/fresh native run must save startup pages, every thirteen-role raw sample, offline reprojection, Runner once-only import, both binary/cache/source identities and both successful PID lifecycles. Existing historical receipts and software controls do not satisfy that remaining gate.

## Concurrent source boundary at freeze

The final expanded combined control run reports **200 passed, 1 failed in 38.34s**. Its sole failure is the existing `test_renderer_other_code_ast_unchanged`: another owner concurrently added the explicitly authorized opt-in storage-probe renderer branch. This gate changes neither renderer nor that AST control and does not weaken the control. Before those shared edits, the preceding 196-control combination passed in 36.51s. Both actual receipts are retained.

The active `gate-source-pins.json` freezes only the two new gate files. Earlier full host freeze receipts are explicitly named `superseded-*` and must not authorize remote preparation. Once shared source is frozen, regenerate and verify the complete source-only freeze, then complete source review before any remote snapshot. The native gate independently rechecks every frozen host file at invocation.
