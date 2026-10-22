# Native source completion and P6 feedback design

**Status:** design updated with a source-only CPU signal inventory. No production code, tests, runtime gate, or remote inputs are changed by this document.

## Decision

Treat `native_instruction_bus_completion.v1` as a source-bound native instruction-bus transfer fact. It may be retained as an intermediate delivery witness, but it does not itself count as CPU consumption, a P6 edge hit, or closed-loop feedback. A feedback hit is eligible only after a separate real consumer event is available and an exact causal join connects source production, delivery, and consumption on one declared path.

This preserves the current proof scope `native_instruction_bus_transfer_completed` and `grants_source_authority=false`.

## Context and current boundary

- The local implementation branch `codex/native-exact-source-completion-20261018` has completed Tasks 1–4: actual issued-read identity, exact live source-binding lookup, issuance at the verified next-PRE handshake, and default-off Runner/fresh-replay integration. Task 5 remains a separate frozen real-process gate and independent audit.
- The event consumer validates the live completion object and joins the selected source admission, host binding, service write, raw accepted/response/completed observations, and exact snapshot before publishing detached references. This is a transport join, not an instruction-retirement or semantic-consumption proof.
- `RuntimeEdgeIndex.match_event` currently recognizes dataflow, source/pulse start, CPU IRQ taken, and MMIO acceptance/delivery; it does not recognize native source completion. `EventProvenance.decorate` therefore leaves this event at `observation_only`, with `resource=null` and no edge candidates.
- P6 requires each of `stage_hits`, `edge_hits`, `state_transition_hits`, and `closed_loop_hits` to include path/source identity and real producer, delivery, and consumer events. A transport completion alone does not meet that contract.

### CPU consumer-signal inventory (2026-10-19)

The Attempt10 target is PicoRV32 at upstream submodule commit `ef203c2b0a3fb793280f5114941416c425c5b461`; its pinned `picorv32.v` SHA-256 is `0836050971b3c6cdd28ac3b1e5719a67fb645161912bef1e472e63995ceb0622`. The current profile exposes `trace_valid` and `trace_data` as observed physical outputs, but `ENABLE_TRACE` defaults to zero and the generated build does not override it. The Runner preserves physical outputs in raw tick samples, while the Attempt10 checker does not inspect either trace signal. They therefore provide no current consumer witness.

The RTL's `RISCV_FORMAL` conditional exposes a stronger RVFI interface (`rvfi_valid`, instruction/order, PC and register data), but the Attempt10 build has no defines and the wrapper does not export those ports. RVFI is a candidate for a separately frozen consumer adapter after the real Task5 gate; enabling it would require a new build identity, complete wrapper/ABI port dispositions, captured samples, and an independent checker. Neither the disabled trace wires nor the unavailable RVFI ports grant consumption or retirement authority. The source inventory is recorded in [the CPU consumer observation report](../../reports/native-cpu-consumer-inventory-20261019.md).

## Goals

1. Preserve a typed, exact-source transfer event as a reusable intermediate fact.
2. Define the evidence required before native-source facts can contribute to P6 feedback.
3. Keep feedback scoped to a declared `RuntimePathContract`, selected source admission, testcase, execution, and reset epoch.
4. Make fresh replay reconstruct the same causal joins using independent owners and processes.

## Non-goals

- Do not infer decode, execution, retirement, architectural effect, or semantic instruction consumption from `valid && ready`.
- Do not grant source authority, input mutation credit, coverage credit, or closed-loop credit from a completion event alone.
- Do not enable an arbitrary same-protocol CPU/IP from this event contract.
- Do not change HARNESS V1/V2 identities, historical schemas, or the attempt6 frozen source, auditor, controller, plan, or remote operation.
- Do not mark any P6 row or phase accepted from design or software evidence alone.

## Evidence model

The future join has three distinct witnesses:

1. **Producer:** the actual admitted source write and its exact source/admission identity. Saved admission JSON or an event with a copied action ID cannot create the producer fact.
2. **Delivery:** the original issued `native_instruction_bus_completion.v1`, with its validated references to the selected binding, service write, exact four-byte snapshot, accepted request, response, and next-PRE completion. This proves transfer completion only.
3. **Consumer:** a separate event backed by an observed CPU-side effect that consumes the exact delivered instruction or resulting source token. The event must be produced by an existing, source-pinned CPU observation or a separately reviewed adapter. Its schema and signal source remain unset until a real CPU signal inventory confirms what can be observed; a journal projection, matching bytes, PC guess, or completion handshake is insufficient.

A feedback record may be emitted only if all three witnesses resolve uniquely and agree on source admission, path, component endpoints, execution, case, reset epoch, transaction/resource version where applicable, and causal order. It must carry the three original journal event IDs. Duplicate publication, missing references, aliases, stale epochs, or order violations fail closed.

`RuntimeEdgeIndex` may identify a declared candidate edge, but candidate matching remains descriptive. An edge candidate is not a hit. Until a consumer witness exists, the completion remains an observation/transport fact and contributes zero P6 feedback hits.

## Feedback semantics

- **Stage hit:** requires a real consumer witness for the named stage plus the exact producer and delivery references.
- **Edge hit:** requires a declared path edge and one unique producer → delivery → consumer chain whose endpoints and order match that edge.
- **State-transition hit:** additionally requires the observed before/after state evidence named by the path contract; completion alone is not a state change.
- **Closed-loop hit:** additionally requires the declared return path and its own real delivery and consumption witnesses. A one-way instruction fetch is not a loop.

All hit identities are deduplicated by path, source admission, case, execution, reset epoch, and the relevant producer/delivery/consumer event IDs. Repeated fetches may remain separate transfer facts but must not manufacture novelty or a return path.

## Replay and lifecycle

- Fresh replay constructs independent CPU, memory, service, Runner, native observer, source session, and process owners. No live completion or consumer token crosses between runs.
- The original and fresh journals are compared only after independently validating their raw references. Normalize only explicitly owned process nonce/identity fields already declared by the native replay contract.
- Reset revokes old-epoch completion and consumer candidates. Abort, finish, or failed joins cannot leave a reusable pending token.
- A failed or contradictory source candidate emits no feedback hit. Preserve the original failure and partial evidence; do not replace a missing consumer with an inferred status.

## Implementation gates

1. Complete and independently audit the frozen Task5 real-process gate before changing the native completion event's runtime identity or evidence projection.
2. Use the source inventory to select and pin a real consumption/retirement observation source, including its ports, semantics, producer path, and reset behavior. For the current build, keep the consumer edge unsupported: the exposed trace is disabled and unchecked, and RVFI is not compiled or exported. If no trustworthy consumer observation is enabled, keep the edge unsupported rather than synthesizing one.
3. Add one narrow consumer adapter and exact join for one declared P6 path. Keep candidate discovery separate from hit issuance.
4. Verify positive, no-consumer, wrong-admission, wrong-path, stale-epoch, duplicate-reference, reordered-event, byte/version mismatch, and fresh-owner cases.
5. Run a real multi-case persistent session with full fresh replay and independent raw audit. Require each P6 feedback class to carry producer, delivery, and consumer event IDs; require extra state/return evidence for state-transition and closed-loop hits.
6. Update the relevant P6 row and runtime/report indexes only from that frozen evidence. One row does not close P6; all five rows and their checklist cells remain required.

## Decision boundary

The current implementation and Task5 gate can establish a source-bound native instruction-bus transfer. This design describes the additional evidence needed for feedback. It does not assert that a CPU consumer event currently exists or that any feedback gate has passed.
