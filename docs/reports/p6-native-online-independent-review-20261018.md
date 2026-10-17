# Independent source review: bounded native online packets

Reviewed the four owned source paths from `b4b4638` through `fee3e52`, followed by causal-tail correction `f30c524`. The narrow review diff was produced with `git --no-optional-locks diff` before the root copy freeze. During the freeze only file reads and this external draft were performed. No imports, tests, source execution, build, native operation or remote command were run.

## Result

No new blocking source finding identified in the fixed, factory-constructed bounded entry. Root's earlier causal finding is closed in source by `f30c524`: the CPU-source value now traverses actual PADOUT write/readback before joining actual PADIN data. Actual consumption, startup/request timing, per-case completion, fresh prefix and controlled response perturbation remain unverified. This review grants no P6 row, retirement, source authority, IRQ or four-hit feedback capability.

## Four-path scope and frozen bytes

The reviewed increment is limited to:

- `src/myfuzz/local_harness/native_session.py`: declared online slots and physical-fetch readiness guard; SHA `af55cf300cf21c154fbc55734a094deb2bcf2c3f2521d00f5bd00ff0721ef95f`.
- `src/myfuzz/scenario/picorv32_native_cpu_example.py`: deferred source uses the same guard before queuing real MMIO; SHA `e65ae928ad663cc1556bf643720a8106ff04c288454f47f75b38dfcbf18b6f49`.
- `src/myfuzz/scenario/picorv32_native_online.py`: immutable packets, restricted source decoder, factory/route contract; SHA `f05da809a1b64d03b91182ac8f19d8dd09d0f8f28d63dc1fcf19b7cd82bf17f4`.
- `src/myfuzz/integration/picorv32_native_online.py`: bounded lifecycle/submit/export/replay wrapper; SHA `4b2a6daed7ff010f169693d25f2adef14664805bf52692b75d25c8f299be333b`.

After root released the original-source Git freeze, independent `sha256sum` reads of all four actual source files exactly matched `docs/reports/evidence/p6-native-online-source-20261018/source-freeze.sha256`. This verifies these source bytes only; no Python import, test or native execution was performed. Supporting existing decoder/session/memory/Runner/adapter sources were read to assess integration; their historical native evidence is not inherited.

## Request and lifecycle reasoning

`declare_instruction_slots` requires the actual session has not started and an admitted `instruction_identity_observation`; it reserves PersistentMemory words through the existing API without materialization. `waiting_instruction_address` uses the last real sample's POST backend request and same-phase physical marker, requiring valid/read and a wholly unmaterialized reserved word. It calls inspection, not `MemoryService.read`. `_native_request_ready` withholds the next actual backend ready in that condition. Accepted-fetch checks reject writes/MMIO rather than silently routing instruction fetches to peripheral data.

The wrapper constructs one fresh memory/service/router/CPU/GPIO set; it declares96 packet source words plus one final guard before `ScenarioSession.begin`. `begin` preloads bootstrap/tails through the original initial-image path and `Runner.begin_test` does not clear that memory. The new session's `begin_case` clears only pending transport/last samples; it retains the declared slot policy and memory. Default non-opt-in sessions have `_online_instruction_slots=False`, yielding the previous readiness decision and acceptance behavior. CPU max_wait1024 is explicit only in the new factory; GPIO remains16 and old fixtures keep their defaults.

The readiness decision is based on **last POST**, not an authenticated complete startup prefix or future PRE prediction. An unobserved first-startup request cannot be withheld by this hook alone. The concrete bootstrap preloads address0 and reaches reserved0x200 through actual CPU instructions; that arrangement is plausible source integration, not measured first-request safety. The actual adapter request-stability and finite wait checks remain; no timeout relaxation or guessed accepted fetch is added. A future native gate must show the first unfilled fetch offered before acceptance, continued stable waiting with ready0, no RAM materialization, then exact admitted bytes consumed after readiness resumes.

## Packet/decoder/actual consumption reasoning

Packets span0x200..0xe00 at32-byte stride: first4 bytes are admitted CPU ADDI x10,x0,u8 or IP-source NOP support; the remaining28 bytes are immutable initial images. Bootstrap fixes x1=GPIO base and x10=0. The corrected seven-word tail is:

`SW x10,PADOUT; LW x12,PADOUT; LW x11,PADIN; XOR x10,x12,x11; SW x10,RAM[0x100]; SW x10,PADOUT; NOP`.

Neither source nor tail modifies x1. Thus the CPU source has a concrete return dependency through peripheral PADOUT readback, and the IP source has an actual PADIN→CPU→RAM/PADOUT computation. The host does not write a reference result into RAM or synthesize a read response. This establishes executable data dependencies in source; only actual bus/sample/event evidence can establish execution or attribution.

Inherited `decode()` and `decode_candidate()` dispatch through the subclass `_decode_case`, which rejects end/misaligned cursors before selection. Normal factory configuration fixes `support_words=1`, so both CPU and IP proposals contain exactly one4-byte fragment at the current packet word. `super().commit()` checks exact current proposal and contiguous fragment range before committing; the subclass then requires4-byte consumption and advances another28. Inherited `commit_candidate()` calls this overridden commit. `switch_proposal` requires a current proposal and materializes through the subclass method, so the normal constructor cannot generate a fresh support-only case after exhaustion. The generic path/query APIs may still describe declared paths after the last packet; those descriptions are not submission grants. The public inherited constructor is not hardened as an arbitrary alternate packet configuration API: this review covers the fixed factory's start/end/support policy.

The final0xe00 guard is declared but never admitted, preventing random first-read instruction generation after packet96. Tail images do not overlap source words or guard. Runtime max_cases is bounded1..96 and checks before admission. Its custom document explicitly denies generic contiguous reconstruction; full replay uses saved actual plan reservations/images, not a freshly guessed generic decoder.

## Case boundary, failure and replay limitations

Each case schedules128 CPU plus128 GPIO operations. Routed GPIO ACCESS may use multiple actual ticks; Runner retains those indirect bounds. There is no evidence yet that128 CPU steps complete every tail and arrive at the next waiting word. If a prior tail remains pending when a later IP source changes, the later pin value could affect that prior read. **The gate must inspect actual packet PCs/request addresses, response joins, MMIO completion and RAM writers against case boundaries before asserting per-case consumption.** The code does not currently impose an end-of-packet completion predicate or certify every returned running receipt as a chain.

Runtime submit executes a decoded case before decoder commit; any exception after submit begins makes runtime terminal and attempts existing finalize without retry. A pure decoder refusal leaves the runtime available for a new candidate. Successful submit does not itself prove fetch, retirement or terminal consumption. Pending real MMIO/response state can cross case boundaries; this is compatible with persistent execution but cannot be ignored in attribution.

`finish_export` records original plan/trace; fresh uses the same factory with fresh processes through `replay_online_session`. Existing replay restores individual reserved words, initial images, warm-up advances, cases and topology and checks manifest. No new native run, full fresh comparison or guard wait has occurred for these bytes. A future gate must retain real first/fresh process identities and full journals, plus a controlled response perturbation detected by an independent checker. No current software checker or declaration substitutes for that actual gate.

## Pure staging boundary

Root reports a completed pure filesystem staging operation:15318 selected files/790380120 bytes, with25 separately materialized independent Ibex Git files, and unchanged before/after original source maps. This review did not execute or independently reproduce that staging operation; the reported counts are not native evidence. The reviewed original source is distinct from `/tmp/myfuzz-p7-i5-staging-6b40ef4`, which root is keeping immutable for subsequent preparation. This document was published only after root released the Git freeze.

## Boundary follow-up review:906e652 — one medium finding

Reviewed the exact integration-only source diff `f30c524..906e652` and updated source freeze. Actual integration SHA read: `35b08a81cfe5833265fb85bd287e8814160242f4b66b0cf3e9b172e6bf321e44`. No tests, imports or native operations were performed.

The new `_require_packet_boundary` compares the real offered/unfilled instruction address to the expected cursor; it also requires CPU pending responses0, no queued Router targets, GPIO pending responses0 and no remaining GPIO settle clocks. It saves actual expectations/pending/ticks on refusal. The first bootstrap check requires the exact initial cursor. The after-case check requires old cursor+32 before decoder/case-count commit, stays inside the existing failure handler and does not advance additional clocks. This addresses the previous incomplete-tail/next-pin risk on successful submissions.

**M1 (medium): before-input boundary refusal is outside the failure handler.** In `submit()`, the call `_require_packet_boundary(..., phase='before_input')` precedes the `try` whose exception handler invokes `_fail(primary)`. If this actual-state guard fails, it records `boundary_failure` and raises, but leaves `_terminal=False` and does not finalize. The caller can retry, call `finish()` or continue interacting with a runtime whose boundary was explicitly rejected. This contradicts the accompanying report's permanent-terminal guarantee. Even though that guard emits no source input or clocks, it can be inspecting an already executed prefix and its failure must not be described as a harmless decoder candidate refusal.

Requested minimal source correction: catch only the before-input guard failure and invoke `_fail(primary)` then re-raise; keep pure decoder refusal outside the fatal submission handler so invalid candidate bytes remain recoverable. Retain original prefix and boundary fields. No budget/tick increase or synthetic boundary is required. Re-review the corrected frozen bytes before staging overlay. The after-case/bootstrap branches have no corresponding handler gap in the inspected source.

### Boundary M1 closed:52de02c

Exact diff `906e652..52de02c` adds a dedicated before-input guard `try/except BaseException` that invokes `_fail(primary)` and bare re-raises. `_fail` sets terminal before attempting existing finalize, so another submit/finish cannot continue from a rejected actual boundary. Pure decoder refusal remains outside that fatal handler; no extra step or changed budget is introduced. Independent actual source SHA read `320269c0f41d47e1392d2120bfcd391208f0d743735f80414e13a8e2785bb6b6` exactly matches the updated four-source freeze. **M1 closed in source; no further blocking finding on this narrow fix.** Previous first-startup, actual consumption, full replay and performance verification limits remain. No tests/imports/native execution were performed for this re-review.
