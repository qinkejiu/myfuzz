# Guarded native fresh replay: source-only design

Status: proposed implementation seam only. No production source changed, no
execution result or new gate, and no inherited actual pass.

## Located behavior

`PicoNativeOnlineRuntime.replay` delegates to `replay_online_session(plan,
self.factory, reference)`. After strict plan parsing and validation the latter
constructs `ScenarioSession(template, factory(), checker=checker)`. Its case
loop therefore bypasses `NativePacketSession.submit_case` and its physical
pre/post packet checks, independent cursor, case bound and terminal failure
handling. An exact trace match alone does not establish guard execution.

The native guarded constructor already declares all 97 four-byte reservations
at `0x200 + 32*i`, i=0..96, by calling the superclass implementation once per
slot. Its own `declare_instruction_slots` deliberately refuses later calls.
The generic replay's unconditional slot-declaration loop cannot be retained
for this subclass. Reconstructing contiguous four-byte slots would also violate
the native packet contract.

## Minimal closed seam

Add an explicit keyword-only `native_packet_max_cases=None` to
`replay_online_session`. None preserves the current generic path. An explicit
integer1..96 selects exactly the code-owned `NativePacketSession`, imported
locally at this construction branch; reject bool and other values. This is a
closed selector, not an arbitrary session factory or success callback.
`PicoNativeOnlineRuntime.replay` passes its actual `self.max_cases` explicitly.
This changes native runtime replay to guarded execution while leaving ordinary
legacy replay callers on the existing default. The selection is independent
of `native_completion_observation` and must also protect native runs with
completion observation disabled.

Before calling `factory()`, validate native-specific saved setup: exact fixed
bootstrap template, canonical ordered reservation list
`[['cpu', address, 1] for address in range(0x200, 0xe01, 32)]`, at most the
selected max_cases, and no register-program or reset timeline. Reject a plan
from a different fixture rather than infer native selection from CPU names,
addresses or arbitrary metadata. Keep existing provenance/runtime-path
validation; native replay must not bypass it. The guarded constructor repeats
template admission as its own invariant.

Construct `NativePacketSession(template, factory(), checker=checker,
max_cases=native_packet_max_cases)` at the existing construction site. Preserve
the trusted-gate match check and runtime-path reconstruction/topology equality.
At the slot-declaration site, native selection instead compares the saved list
exactly against the constructor-owned `session._instruction_slots`, including
order, count, stride and end guard. Perform no new declarations and do not
ignore an allegedly harmless duplicate. The generic branch retains its loop.

Keep the existing manifest recomputation and exact reference manifest hash
check before `begin()`. Keep the original encoded plan hash check, original
saved cases/source roles, every saved `warmup_advances` entry, every case's
schedule and support bytes, and the single final `finish()`. Replay does not
call the runtime's begin warmup loop, decode candidates, redraw source choices,
commit a decoder or add clocks to reach a guessed boundary. After the saved
warmup, the first guarded submit checks the actual offered address and pending
queues; all later submissions check both actual packet boundaries.

The existing final comparison remains whole-prefix: ordered events via
`zip_longest`, terminal failure, scheduled source ticks, source admissions,
status, local ticks, semantic hash and manifest hash. Retain all mismatch
context. Reservation or guard failure is a refusal/failure, never an excuse
to filter events or mark replay matched. Fresh factory invocation constructs
new memory, Router and sessions; `begin()` must create fresh hardware
processes. Existing verified artifact/build cache reuse can support warm fresh
without sharing live state. Cold cache policy is a separate caller concern.

## Scope requiring a follow-on before acceptance

The current plan/manifest has no native packet-specific schema or max_cases
field. The closed option above preserves and validates its actual saved plan
and existing manifest, but the caller-supplied max_cases is not independently
recoverable from them. A packet-aware versioned plan/manifest contract should
bind max_cases, stride32, source4/tail28, exact97 reservations, bootstrap/tail
bytes and code-owned producer contracts before standalone persisted-document
reconstruction is accepted. Do not claim the minimal constructor seam alone
implements that C4 contract.

NativePacketSession guard failures can occur outside the superclass terminal
failure recording phases. Generic replay's expected-failure handling must not
catch and certify such failures merely because an earlier trace prefix agrees.
Initial implementation should refuse unsupported native guard/decoder-commit
failure replay until a typed native terminal record binds the attempted case,
cursor, failure and complete original event prefix. A successful guarded
replay is the bounded first target; terminal-failure serialization remains
explicitly separate work. There is no decoder commit during replay because
the actual submitted cases are already saved.

## Keep observation identity normalization separate

The retained artifact factory already captures the explicit completion
observation choice. Guarded reconstruction must use that same factory and
leave source/build/artifact/manifest equality checks intact. Actual process
nonces differ in a genuinely fresh run; this constructor change must not
erase them or weaken event comparison. Any opt-in normalization policy for
fresh native observation identities is a separate versioned, source-pinned
comparison change: validate per-run scope/continuity and consistently map only
declared fresh identities across every occurrence. Preserve signal values,
ticks, phases, transaction sequences, memory writer/source attribution and
all evidence joins. Until implemented and independently verified, an exact
nonce mismatch remains a mismatch. Default legacy comparison stays exact.

## Static review boundary

Read `integration/picorv32_native_online.py`,
`scenario/native_packet_session.py` and `scenario/session_runtime.py`, including
manifest construction, reservation recording, plan encoding and the complete
replay path. No project imports, tests, frontend/build/model invocation,
native process or remote operation was performed. Only this report is changed.
