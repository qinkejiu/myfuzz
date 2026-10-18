# Independent native observer source review

Reviewed `feb2393` against the passive native taps and guarded session paths.
This is a source-only review: no tests, project imports, builds, frontend,
models, or remote commands were run. The frozen `c924` backend gate grants no
runtime acceptance to these changes.

## Important: finish can omit the final native completion

`src/myfuzz/local_harness/native_session.py:224-226` and
`src/myfuzz/scenario/picorv32_native_cpu_example.py:406-409` clear `_pending`
immediately on backend response consumption. At that point the new observer is
only in `response` state (`native_cpu_events.py:156-157`); its actual native PRE
valid/ready completion requires the next tick (`native_cpu_events.py:104-111`).
Both public pending counts ignore that remaining observer transaction
(`native_session.py:123-124`, `picorv32_native_cpu_example.py:334-338`).
Runner quiesce therefore stops after backend consumption and can report
`drained` without executing the native completion tick
(`runner.py:3034-3053`, status at `3059-3062`). There is no observer close hook
that refuses this incomplete terminal prefix. The wait bound cannot detect it
because it is checked only on a subsequent observed tick.

Minimal fix: for opt-in observation, include the still outstanding native
transaction in the session's drain accounting (or a dedicated pending event
count), preserving exactly one count when `_pending`/queued work overlaps it.
Quiesce must execute the actual next CPU tick; do not project completion from
the previous POST ready offer. Normal close should refuse/report an incomplete
observer transaction; reset must explicitly cancel it. Apply to base and
Deferred paths while retaining default-disabled behavior.

## Scoped source findings

No Critical finding identified in the examined source. The observer correctly
distinguishes response-consume POST ready from next-PRE native handshake,
checks the instruction marker across the outstanding tuple, advances memory
sequence for data and instruction requests together, and binds the actual RAM
read snapshot after service. Deferred calls the hook once on its own step path;
it does not also call the base step. Runner's native dispatch bypasses the OBI
trace-set observer. Completion events remain transfer-only, explicitly denying
source authority and retirement; data transfers are not labeled instruction
transfers. This does not establish the archived 47-transaction runtime result,
source-byte consumption, or successful reset/finish behavior.
