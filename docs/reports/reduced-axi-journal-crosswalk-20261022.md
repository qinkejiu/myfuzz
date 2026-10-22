# Reduced AXI production journal crosswalk: implementation progress

## Approved scope

The user approved the [source receipt/lifecycle binding design](../superpowers/specs/2026-10-22-reduced-axi-journal-crosswalk-design.md)
on 2026-10-22. The [five-task plan](../superpowers/plans/2026-10-22-reduced-axi-journal-crosswalk.md)
covers bounded issuance, session/observer capture, role-aware consumer,
Runner integration and a native first/fresh gate. Tasks1–5 are complete for
the reviewed generated Reduced AXI CPU/RAM observation path. This is bounded
observation evidence; it does not grant runtime/semantic authority or generic
CPU/IP acceptance.

## Task 1: bounded source issuance software gate

The new [ObservationStreamSource](../../src/myfuzz/scenario/observation_stream.py)
is a generic issuance component. It does not admit a session by itself.

- Exact six-field binding; strict finite JSON rejects tuple coercion and
  non-string dictionary keys. Observer contract is a nonempty dictionary.
- Opaque live tokens belong to one source. Detached input/lookup/identity
  copies, FIFO ACK, exact pending byte release and stale/foreign-token refusal.
- Source operation ordinal includes empty operations; source record ordinal
  counts every observation, not only raw rows. ACK does not reset lifetime.
- Separate cumulative-operation, pending-operation, individual-operation and
  pending-byte bounds. Canonical byte accounting includes content_digest.
- Read-only active/sealed/poisoned state. Poison takes precedence over seal;
  diagnostic lookup after poison cannot authorize subsequent import.

The implementer preserved an initial missing-module RED and a state-property
RED (two failures before that API existed). Focused tests then passed71.
Independent task review passed both specification and code-quality checks,
including additional cyclic/deep JSON and hostile-token checks.

The actual six-module combined gate is **148 passed, 67 subtests passed**,
exit0,12.02s. This includes the new71 cases and existing Reduced AXI, AHB,
OBI and coverage regressions. [Raw command log](evidence/reduced-axi-journal-crosswalk-20261022/software-task1-attempt1/pytest.log)
and [process/input receipt](evidence/reduced-axi-journal-crosswalk-20261022/software-task1-attempt1/verification.json)
are saved with the selected12 source/test input bytes and pre/post hashes.
This is a selected-input freeze, not a complete source/toolchain closure.
No new native execution, build or remote operation was performed for this task.

## Task 2: receipt/lifecycle source software gate

The admitted reduced protocol session can now explicitly enable an observation
source before its first native begin/command. Disabled sessions allocate no
source queue and preserve their original close/reset event behavior. The source
captures exact parsed DriverReceipt fields, original command/reply, process-local
sample tick and cumulative tick separately. Lifecycle begin/end operations,
including empty scopes, share an ordered issuance stream with receipts.

Emit-time detached snapshots protect against public buffer mutation. Live
ownership checks bind the actual session, exporter, source, observer, listener,
component, artifact, contract and exact configured limits. Removing/replacing
these cannot restore a disabled fallback. Capture/ordinal failures poison source
integrity; an intact genuine protocol violation remains authentic failure
evidence and blocks future transport. These are distinct states. Native process
cleanup remains in finally even when integrity checks fail.

An explicit seal records prior operation/observation totals, kind counts and a
recomputable content-digest chain. ACK and reset preserve lifetime counters.
The seal commits recording integrity, without inventing a reset/cancellation or
requiring legitimate protocol pending requests to disappear.

Initial independent review found two P1s: live ownership drift and a capture
error masked as an ordinary observer violation. Both were reproduced and fixed.
Re-review then found a P2 Python numeric-type equality gap in limit declarations;
`1 → True` and `1 → 1.0` controls now refuse before transport. Rejected reviews,
source snapshot and all RED logs are retained alongside the final evidence.
The [final independent review](evidence/reduced-axi-journal-crosswalk-20261022/software-task2-attempt1/task-2-final-review.md)
passed both specification and quality checks and independently recomputed seals.

The final root command froze20 selected source/test inputs before execution:
**234 passed, 2 native tests deselected, 96 subtests passed**, exit0,20.28s.
[Raw log](evidence/reduced-axi-journal-crosswalk-20261022/software-task2-attempt1/pytest.log),
[process/input receipt](evidence/reduced-axi-journal-crosswalk-20261022/software-task2-attempt1/verification.json),
selected-input archive, failed controls and reviews are saved. All selected
inputs matched before/after the command. This is not complete source or toolchain
closure. Parser fixtures use real DriverReceipt/parser code with software
transport fixtures; this task ran no new native/build/remote gate.

## Remaining acceptance

Task3 role-aware journal consumer has passed independent specification and quality review. Task4 production Runner import,
durable sidecars/seals and Task5 actual native first/fresh remain open. Task2
alone does not register a source with Runner or grant protocol certificates.

The consumer must reproject trusted issued receipt samples, not altered journal
rows; preserve same-edge AW/W repeated reference roles; authenticate every raw
scope independently; detect a missing final derived record and keep complete
recording integrity separate from legitimate protocol pending.

No CPU/IP name branch, retirement, MemoryService writer/version, DMA effect,
ISR or semantic authority is granted by these source software gates.
P6/P7-E/P8 and the complete six-CPU/four-IP objective remain open.

## Task3 software acceptance — complete

The full-journal consumer now replays original command/receipt witnesses with a
fresh observer and checks exact original spans, role-preserving sidecars, global
IDs, complete scope ownership, lifecycle operations and the actual terminal seal.
Its recording completeness and protocol pending/outcome are separate. Rehashed
journal observations cannot substitute for the original issued receipt oracle.

Root verification: **430 passed, 2 native tests deselected, 96 subtests passed**,
exit0,20.33 seconds. All24 selected source/test inputs matched before/after.
[Process/input receipt](evidence/reduced-axi-journal-crosswalk-20261022/software-task3-attempt1/verification.json)
and [independent review](evidence/reduced-axi-journal-crosswalk-20261022/software-task3-attempt1/task-3-review.md)
are retained. Archive SHA256: `c226b9e8d31dc734cf9530cb8a9507e302eaf27a94f9037efe3b5df449b6ced9`.
This is a selected-input freeze, not complete source/toolchain closure.

Task4 Runner admission/import and durable reload are now being implemented;
Task5 native first/fresh remains open. These software checks grant observation
consistency only, with runtime_accepted=false and semantic_accepted=false.

## Task4 initial software delivery — review requested changes

Production Runner admission/import, role-preserving sidecars, explicit seals,
full-global consumer feeding, bounded reports and durable JSONL/zlib reload have
been implemented. Root's frozen initial gate: **492 passed, 2 native deselected,
96 subtests passed**, exit0;28 selected inputs unchanged. This delivery is **not
accepted**: independent review found Important R4-1, a configured source operation
byte cap could be exceeded after native launch/one transport rather than refused
before effects. Caps100/1000/5000 reproduced the gap in software transport fixtures.
A conservative lifecycle/receipt fit preflight and boundary tests are being fixed.

[Initial command receipt](evidence/reduced-axi-journal-crosswalk-20261022/software-task4-attempt1/verification.json)
and [rejected independent review](evidence/reduced-axi-journal-crosswalk-20261022/software-task4-attempt1/task-4-independent-review-rejected.md)
are preserved. Selected-input archive SHA256:
`62992e47d9b0ccf46e23c4bd3685a6164597d99760056573a823212bc0c115be`.
This is not complete source/toolchain closure. No Task5 native run has started.

Task5 verifier preparation also exposed a fresh-process import regression:
`from myfuzz.scenario.runner import ScenarioRunner` fails with a circular import
through the new coordinator/consumer and generated register factory. Root retained
the standalone failure; R4-2 is included in the same fix wave with independent
subprocess import tests. Test import order is not an acceptance workaround.

## Task4 Runner production import — software accepted

The corrected Runner path admits actual Reduced AXI source ownership before identity,
imports immutable operation receipts/original observation rows and role-preserving
journal sidecars, feeds every global event to each bounded consumer, and reloads the
complete recording through JSONL/zlib views. Empty lifecycle/seal operations and
legitimate pending state remain explicit. Partial append/ACK failures poison the
stream and cannot retry; reports remain observation_only.

Final root frozen gate: **519 passed, 2 native deselected, 96 subtests passed**,
exit0; all28 selected inputs unchanged. Selected-input archive SHA256:
`ca1c85ddb594a2b0eff4aa0b1d96dab68c60ff6d9e8fd0cacdccc866d848bc4d`. [Process/input receipt](evidence/reduced-axi-journal-crosswalk-20261022/software-task4-rereview-attempt1/verification.json)
and [final independent review](evidence/reduced-axi-journal-crosswalk-20261022/software-task4-rereview-attempt1/task-4-independent-review-final.md)
report Spec PASS and Quality PASS after two findings were reproduced and fixed.
The rejected492-test initial handoff remains preserved as historical evidence.

At the Task4 handoff, Task5 executable review found three important gaps in the
first/fresh comparator and build input archive. The initial candidate was
rejected and preserved; its repair and acceptance are recorded below.

## Task5 native first/fresh — accepted for the bounded observation-only scope

The corrected verifier received an independent **Spec PASS / Quality PASS**.
Root and independent software reruns each passed **37 tests**. The R5 fixes
validate original service transaction keys, RAM read/write callback preimages,
memory-cell origins and dependency edges before mapping; archive every declared
build input and every materialized first/fresh cache input; and validate the
original final-state report map before replacing it in the comparison view.
The corrected candidate hashes, rejected predecessor and review receipts are
retained in [Task5 readiness report](../../.superpowers/sdd/reduced-axi-crosswalk-20261022/task-5-report.md),
[frozen review manifest](../../.superpowers/sdd/reduced-axi-crosswalk-20261022/task-5-r5-freeze.json),
[independent executable review](../../.superpowers/sdd/reduced-axi-crosswalk-20261022/task-5-r5-independent-review.md),
and [root software rerun](../../.superpowers/sdd/reduced-axi-crosswalk-20261022/task-5-r5-root-rerun.log).

The supervised [native attempt1](evidence/reduced-axi-journal-crosswalk-20261022/native-attempt1/)
exited0; pytest reports **1 passed in33.55s**. It launched two separate
generated native processes: PID33519 / execution
`67161b1efa43497da140596cf45dcc68` and PID33621 / execution
`c9e5ca6e1e374aaf94de6a66520a29e6`; both returned0 and were reaped. Each run
recorded55 PRE samples and408 global journal events. The measured program
performed same-edge AW/W stores of53 at tick42 and54 at tick54, received two
successful B responses, and read back53 on the physical data channel at tick45.
Eleven instruction ARs were accepted. The physical predicate and passive
READY/CMD/RESULT/ACK chronology were independently joined to the parsed receipts.

The full first/fresh normalized journal views are equal, each with408 rows and
SHA256
`d98c76736924015210cc9cfe64ee82879487a5ad63c0f2e7791bcc3ea24afe7a`.
Original nonce-bearing recordings remain unchanged. The source seal and
recording-integrity report are complete; **one instruction read remains pending**
at terminal seal, while all data-channel pending slots are clear. Complete
recording status therefore does not mean that every protocol request drained.
No retirement or instruction-consumption claim follows from the fetches.

Build identity is `8ca68c09d012ec6617ec4461c714ccc2dc1977baa3bdd1b1f92d770197ea82f4`,
with357 declared byte inputs and binary SHA256
`2215ff99095a2c5f593c8bdc8d9fbcadac95ff6b00d99c6ce5c83f56be8763cd` shared by
both runs. The external supervisor inventory covers3295 members and
91,097,941bytes. The [supervised terminal/resource receipts](evidence/reduced-axi-journal-crosswalk-20261022/native-attempt1/terminal.json),
[root independent raw/archive audit output](evidence/reduced-axi-journal-crosswalk-20261022/native-attempt1/root-independent-audit.json),
[audit invocation receipt](evidence/reduced-axi-journal-crosswalk-20261022/native-attempt1/root-independent-audit-receipt.json)
and [independent saved-evidence review](../../.superpowers/sdd/reduced-axi-crosswalk-20261022/native-attempt1-independent-audit.md)
are retained. The independent review rechecked all original/durable rows,
source/archive bytes, process identities and the physical sample joins.

All outputs remain `authority=observation_only`,
`runtime_accepted=false`, `semantic_accepted=false`. This gate does not cover
W-before-AW/AW-before-W, overlapping old-B/new-AW-W, physical error or exclusive
responses, in-flight reset cancellation, all lane variants, bursts, retirement,
DMA/ISR, physical shared SRAM/bridge or generic same-protocol onboarding.
P6/P7-E/P8 and the complete six-CPU/four-IP goal remain open.
