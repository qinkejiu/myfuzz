# E2 ordinary-access receipt trust-boundary review

2026-10-12; independent read-only source review by `review_d1_c7`. No production edits, test execution or RTL process. This document proposes receipt-binding acceptance tests; it does not certify an implemented verifier or promote a capability level.

## Current boundary

The ordinary assembly's validated native APB trace establishes actual setup/access/response observations. It does **not** yet bind an APB span to a particular CPU transaction. APB's transaction key remains null and its explicit identity gap must remain visible. Matching address, direction, value, neighboring event IDs or observed case labels cannot fill that gap.

Relevant existing paths:

- `scenario/router.py:112` dispatches a routed-context API only when the target exposes `routed_register_access_enabled`. Otherwise ordinary accesses call `write_register`/`read_register`; those APIs issue `ACCESS_GPIO` but return no transaction-scoped raw-span receipt (`local_harness/gpio_session.py:373`).
- `router.py:127` accepts through the actual `TransactionLedger`, then `drain_one` executes the selected target. The callback-confirmed routed delivery is published only after callback success (`router.py:197`). An executed target and an acknowledged CPU delivery are separate facts; callback failure must preserve that distinction and must never cause target reexecution.
- The internal-observation variant's `gpio_session.py:69` already binds an actual TransactionKey, command sequence, target reset epoch and access ID. Its unique target request/access/response checks at lines 154–199 are useful design references, but this API requires its own observation contract and internal probes. Do not enable or weaken D4 admission merely to reuse it for ordinary trace-only sessions.
- `gpio_session.py:283` retains detached samples from the parsed receipt. `runner.py:1869` drains samples later and adds a producer event ID and the session's current reset epoch. Neither the generic sample nor this later producer ID identifies the originating ACCESS command. A CPU step may indirectly clock several targets/commands before one drain. Global journal adjacency therefore is not a command boundary.
- `runner.py:1956` drains independent router and target streams and assigns journal IDs. The `producer_event_id` is the outer drain trigger; target raw observations and router delivery rows can be logged in different stream order. Required causality should be expressed by exact authenticated references, not invented total ordering among these streams.
- D4 `gpio_register_evidence.py:193` onward requires native contract/probes, continuous physical edges, exact transaction and access identities. It rejects missing accesses even for same-value native writes, conflicts, epoch discontinuities and capacity exhaustion. Its certificate describes an internal register version, which ordinary APB evidence cannot establish.

## Required receipt design

Create a code-owned receipt while the actual router invokes the actual target command. Bind the actual source TransactionKey, pinned ledger/router/window/target object identity, endpoint, absolute address and decoded offset, operation/full-word lanes/value, actual target epoch, parsed driver execution/command sequence, and exact command-local sample interval. A caller must not supply authoritative command IDs, raw/base refs, successful status or a complete receipt.

Record the command's epoch and process scope at receipt creation, not at later drain. Pending samples must either retain that identity across a reset/drain or cause explicit incomplete refusal; stamping old samples with a newer session epoch must not authorize a match. Memory generation, source epoch and target reset epoch are separate domains; do not assume their integers must equal. Require each to match the actual object/transaction to which it belongs.

Runner should resolve raw IDs from a private receipt handle after journal publication, then rebuild base request/accept/response with the pinned actual native normalizer/checker. A narrowly scoped in-process single-use token or equivalent private object registry is preferable to accepting a public JSON receipt. Saved records and canonical hashes are comparison data only. If replay supports these receipts, fresh original requests must generate new actual command receipts; saved refs must not be fed into their authority registry.

The command span must contain exactly one valid APB request followed by its acceptance/response, stable request controls across setup and any waits, ready/error checks, and matching measured read data. All constituent raw rows must belong to the same actual target, execution, command and target epoch. A command may include idle ticks; require exact membership in the command interval, not all journal rows between two IDs. Only trusted code-derived base refs may be retained, with their request relationships checked explicitly. Reject malformed widths/types, impossible ordering, absent setup/access, extra competing accesses and incomplete response.

Separate receipt scopes: `target_access_observed` can describe successful APB execution; `cpu_delivery_confirmed` additionally requires the actual source callback/ledger completion. Neither scope proves CPU retirement, register persistence, a functional side effect, an interrupt, a prerequisite or aggregate L2. An RMW's pre-write read does not prove post-write storage. A later CPU readback is a separate future verifier rule.

Bound receipt pending count, raw span length, token fanout, text/detail sizes, retained transaction/command IDs and dedup sets. Refuse on exhaustion without discarding uncertainty or allowing an old receipt to be accepted as new. Pin provider/runner/session/router/ledger/window target and validated artifact/projector configuration; drift must fail before publication and prevent later recovery from replayed saved evidence. Export detached bounded documents.

## Mandatory software rejection matrix

| Mutation or failure | Required result |
| --- | --- |
| Identical callback/receipt/raw retransmission | At most one receipt/certificate; no extra device command or callback |
| Same transaction or command ID with changed payload, target, epoch or sample | Permanent conflict/incomplete for that provider; prior historical records remain historical |
| New IDs over the identical physical command span | No second access credit; physical span/command identity dedup |
| Delete setup, ready access, response, router acceptance or CPU callback confirmation | No claimed complete chain; distinguish observed target access from confirmed delivery |
| Same address/value in another transaction or command | No substitution, including adjacent commands in one CPU step |
| Swap GPIO A/B with identical profile or identical tick/value | Refuse via actual window/target instance identity, even when saved report is rehashed |
| Change source execution/channel/sequence/source epoch, target epoch or driver execution | Refuse; valid distinct source/target epoch integers are not themselves a mismatch |
| Reset between command phases, receipt creation and drain, or reuse old receipt after reset | No relabeled/revived old command; pending receipt invalidated or strictly preserved as historical only |
| Move a raw/base ref just outside the authenticated command interval | Refuse, even if controls/data equal; producer/case adjacency is insufficient |
| Replace normalizer/checker/artifact/profile/window/ledger or mutate trace tap mapping | Repeated pre-publication rejection; saved cached configuration cannot hide drift |
| Caller-supplied journal refs, fake receipt JSON/token, rehashed saved certificate | No authority and no registration/command mutation |
| Wait-state request changes, ready=0, error=1, duplicate ready beats, read-value mismatch | No successful access receipt; native write effects before ready remain possible uncertainty |
| Lost reply or callback raises after actual access | Preserve uncertain/target-only outcome; retry never reexecutes target |
| Capacity boundary, oversized transaction strings, boolean integer IDs, caller mutation | Bounded fail-closed state, detached retained/output data, no recovery by eviction/reset |

Add a positive control for every mutation family: actual router dispatch plus parsed software transport receipt, exact once callback, explicit wait-state transaction, and successful two-target operation with distinct identities. Validate that verification does not alter instruction slots, RAM cells, Session admissions, weights, runtime identity or the journal. Default-off ordinary factory behavior and serialized plan bytes must stay unchanged.

## Reusable real software fixtures

1. `tests/scenario/test_register_program_runtime.py:factory` / `installed`: actual rendered three-session factory, actual memory/service/gate/ledger and software CPU `_serve` callback, no driver process. Use its 64-byte budget variant for actual RMW requests. Extend its fake parsed transport replies with command-local APB samples, then route through the actual router instead of directly feeding a verifier dict.
2. `tests/scenario/test_native_apb_protocol_runner.py:artifacts` and `runner_session`: actual planner/renderer/native contract and Runner projector. The existing provenance test supplies real-format eight-tap setup/access observations and confirms original raw refs. Useful for malformed/tap/epoch/base-ref mutations, but its SimpleNamespace transport alone cannot prove source callback or authority; combine it with the actual router/ledger fixture.
3. `tests/scenario/test_gpio_register_evidence.py`: existing reset-before/after-barrier, duplicate barrier, same-value overwrite, deleted-access, conflict, capacity and detached-report tests provide lifecycle patterns. Preserve its internal-probe contract unchanged; ordinary access tests must not manufacture its probe states or certificates.
4. Existing completed directed artifacts can inform command shapes and identity-gap assertions. Reading/reingesting their saved events is only a reproducibility/parser test, never a live receipt grant or actual callback positive control.

The first implementation checkpoint should deliver only exact actual-command receipt binding plus its rejection matrix. Internal version/readback/functional certificates and any capability promotion require separate observed rules and acceptance work.

## Runner-association implementation review checkpoint

The first target-command package's independent 19 tests passed after strict scalar/context validation, measured APB-span rebuilding, lifetime access IDs and stable private process ordinals were added. Two additional boundaries must be explicit in the next Runner package:

1. **Callback provenance is not the delivery row's boolean.** Router delivery rows are public mutable dictionaries. The ledger transitions to complete before the source callback. A synchronous `transact` records `source_delivery_confirmed=False`; changing that row to True does not establish an actual CPU callback. A callback failure can also leave a complete target ledger receipt. Require a private code-owned confirmation handoff or retain target-only scope. Actual installed container identity and a complete ledger entry alone are insufficient.
2. **A public sample ref is not immutable command content.** The target registry's exported receipt binds command span/context/read result, but does not include a command-sample content digest. Its sample queue carries public `{access_id, command_scope}` tags. Before draining, a caller can replace same-tick samples while retaining those tags. Rebuilding a valid APB boundary only checks the new content's validity. Exact association requires private command-time compact content/digest and a trusted handoff, or refusal when this link cannot be authenticated.

Necessary independent tests use the actual rendered factory, parsed software command transport and actual CPU router/ledger: mutate synchronous delivery False to True; append a fabricated callback-success row after actual callback failure; replace a tagged queued sample before drain; substitute another actual target's same-valued span; mutate journal raw/base fields after ingestion; and import a fully rehashed saved association into a fresh Runner lacking its command receipt. Every negative must leave associations/verified counts unchanged and must not issue commands. The malformed saved rows may be logged as untrusted input, but must not authorize a match.

The command-content hash and private source-callback confirmation additions passed independent software checks: public synchronous delivery flag changes and fabricated failure-path rows cannot obtain a confirmation; callback returns are detached; tagged raw mutation does not change the original parsed phase digest; changed driver execution/target epoch prevents current digest lookup.

Further actual-CPU admission checks require the original `GeneratedCve2Session._serve` completed-code object, closure self/key/write, matching request evidence, exact final pending response and counter update. Independent direct-router/noop, changed closure key/self/write and callback replacement after an initial preflight tests were first RED and then GREEN (six checks). These remain association checks, with all grants false.

A subsequent independent pre-command test found decoded queue drift: after actual `_serve` acceptance, changing queued lane enable, data32 or offset passed preflight. Three RED tests are in `test_ordinary_apb_access_evidence_boundaries.py`; the offset/data variants can direct a physical command different from the original CPU request before a later acceptance comparison. Preflight must purely reconstruct the decoded window/lane/data/offset from its captured actual payload and reject drift before native target ticks or ACCESS. This observation records the review checkpoint; its eventual fix must be verified separately.

Final collector checkpoint: SHA-256 `e56766d4c021dbeb22e62950d385e4f4f85a4a2d9e06e8a66c54543916e7f49c` adds pinned pure router decode reconstruction and exact typed/canonical comparison before target commands. The three queue-decode RED checks are GREEN. A missing queued delivery journal reference now produces an incomplete association rather than a complete target-only fallback. The independent boundary module's 16 instances passed within the final three-module run (42 passed, one unrelated existing Runner fixture failure; 25.02 seconds). That fixture issued a second `_serve` before consuming the first pending data reply and must model the actual CPU response consumption. Production review found no remaining P1/P2 at this checkpoint; this is software-only association validation with no RTL execution, no verified/storage/functional grant and no active prerequisite.
