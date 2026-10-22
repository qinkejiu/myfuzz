# Reduced AXI journal references and observation consumer

Status: user approved the recommended design on 2026-10-22; implementation
and acceptance remain open. Subsequent clarifications below preserve its scope.

## Objective

Close the production gap between reduced AXI observer-local references and
actual Runner journal IDs. The consumer must operate on the declared reduced
dual single-beat protocol, without branches on CPU/IP/project names. Preserve
original observer records and expose auditable request/response observations.
This is one required part of CPU/IP event expansion and same-protocol reuse;
it does not complete P6/P7/P8 or the six-CPU/four-IP objective.

Existing basis: `reduced-axi-reference-lifecycle-20261022.md` in reports,
`ReducedAxiObserver`, `GeneratedReducedAxiCpuSession`, and Runner's
`_append_external_events`. The observer's record index is lifetime-monotonic;
Runner IDs include scheduler and other components, so those spaces differ.

## Alternatives

1. Recommended: explicit source-issued stream binding and reference sidecars,
   plus a bounded observation consumer that reprojects the raw stream.
   Original observation fields and local reference values remain intact;
   journal identity is added in separate records.
2. Replace local references with Runner IDs inside the original observations.
   This changes archived record meaning and complicates source comparison.
3. Infer an offset from a component name or current list length. Interleaved
   records, in-place drains, resets and reused names invalidate the inference.

## Source and stream admission

A declared observation-export capability binds the actual session and
observer object to the runtime artifact digest, exact observer contract,
source component and a Runner-local stream ordinal. Admission verifies the
reduced protocol variant and signal shapes, never a CPU/IP name. A runtime
observation schema label alone cannot opt an arbitrary object into trusted
source export. An opaque live issuance handle binds export to that admitted
source; serialized handles are not treated as authority.

The durable stream identity includes the explicit stream ordinal and immutable
session/artifact/contract identity. Native execution identity remains in each
original scope, including across process restarts. Replacing a session or
observer requires a new binding; reusing the component name cannot reconnect
old references. Binding events precede observations and join into the saved
Runner identity. `id(list)` is never a durable stream identity.

Before observation, the session seals a detached native command receipt witness
(execution identity, command sequence, tick, exact sample and canonical digest)
after its existing parser/physical-shape checks. A controlled issuance/lookup/ack
API exports this witness; it cannot be reconstructed from mutable runtime_events.
The source captures a canonical record digest and lifetime record sequence at
emission, before exposing the mutable runtime event list. A bounded export
contains detached record copies and their issued sequence/digest. The importer
checks the copied records against this issued source state before journal
append. A hash supplied by an unadmitted record itself is insufficient.
Issued bookkeeping is released only after successful import acknowledgement;
it is not an unbounded second history. Export/append/ack failure poisons the
stream rather than retrying into duplicated effects.

This issuance proves consistency with the admitted observer output, not RTL
or cryptographic trust. The current generated driver/parser and artifact
checks remain the source of physical-receipt admission; this work must not
invent an independent native transaction ID or a stronger source claim.

## Reference map and original records

Runner's integration point is `_append_external_events`, where
`runtime_observation` records receive their actual event IDs. The GPIO/UART
conditional `_drain_causal_gpio_events` cannot be the only integration point.
Both list-backed and file-backed journals use the same capability path.
Legacy observations without the capability remain observation-only and get
no verified crosswalk or consumer report.

Every exported observation has a lifetime record sequence. A raw observation's
existing `raw_event_ref` must equal its issued sequence. The stream checks
strict increasing contiguous record sequences, not contiguous raw refs:
derived records and reset records occupy sequence positions too. Booleans,
floats and strings cannot substitute for integer indices.

Append the original observer record with normal Runner envelope fields;
never rewrite its scope, local refs, pins, payload or authority flags. A
`reduced_axi_journal_binding.v1` sidecar records stream identity, source
sequence/digest, original event ID and role-aware resolved journal references.
It is a mapping record, not a transaction or functional certificate.

Binding explicitly records both the Runner component alias and the declared
source_component; aliases may differ, but each must match its registered
value: journal.component == binding.runner_component, while
record.component_id == scope.source_component == binding.source_component.
No equality between the alias and source name is required. Every raw scope independently matches an issued session lifecycle
witness, not merely another untrusted observation with the same claimed scope.

Raw-reference lookup uses (stream identity, local raw ref). Each resolved raw
record must precede its user, match the complete request scope and component,
and match its original issued digest. Scope consists of execution_id,
testcase_id, reset_epoch and source_component; check each field and JSON type.
Duplicate raw definitions, missing/forward references, cross-stream/epoch or
altered source records refuse verification and poison that stream.

Reference fields are kind-specific: raw_event_refs, complete.request_refs,
and reset.pending_request_refs. Reset contexts are nested endpoint →
read/aw/w/write → null or context containing refs and metadata. Preserve roles,
list order and multiplicity: same-edge AW and W legitimately reference the
same raw record twice. Unknown kind/shape or hidden unsupported reference
fields refuse rather than being silently ignored.

## Observation consumer and reset

Lifecycle operations, native receipt witnesses and their emitted observation
spans share one monotonically ordered source operation sequence. Record each
operation even when it emits zero observations. A command witness binds the
exact record-sequence span produced by that command. No independent lifecycle
and sample queues may silently reorder operations.

A separate consumer follows the complete unchanged journal and its IDs,
including unrelated records and scheduler barriers. It checks sidecar/source
joins and replays the exact samples from issued native receipt witnesses
through a fresh ReducedAxiObserver; it does not treat journal raw rows as
the source oracle. Compare both journal raw and derived rows to that output.
Each issued measured sample must correspond to exactly one raw row. A raw
without its receipt, missing raw for a receipt, or duplicate receipt use
refuses. It compares the entire ordered original observer projection, including
payloads, flags and reset contexts. Reprojection shares the observer algorithm
and is therefore a consistency check, not an independent protocol oracle.

The consumer reports bounded AR/R and AW/W/B observations, request and
response raw/journal refs, actual IDs, response status, and AW/W ordering.
A successfully mapped reference alone issues no transaction result. Only an
exact completed reprojection chain may appear as a verified boundary
observation. Error RESP 2/3 is an observed error outcome; unsupported exclusive
RESP 1 and observer violations remain refusal diagnostics. Authority stays
observation_only, runtime_accepted=false and semantic_accepted=false.

Persist issued begin_scope/end_scope lifecycle witnesses, including empty
scopes and initial begin_scope (which currently emits no observation row).
Reject reopening an already closed identical scope within one stream.

Lifecycle witnesses alone drive begin_scope/end_scope calls on the replay
observer. The resulting reset row is compared with the original reset; the
reset row does not itself drive a second lifecycle transition.
At reduced_axi_reset, first validate every old-scope pending reference and
its cancellation context, then retire old pending state and bind the declared
next scope or end scope. Retain lifetime sequence watermarks and historical
counts. A global reset_barrier does not fabricate a source reset receipt or
silently forgive an unfinished observer prefix. A complete report with an
unmatched source transition, partial export or missing sidecar is unverified.
A report distinguishes a checked prefix with legitimate pending requests
from a sealed complete recording. finalize requires the expected derived
queue to be empty; deleting the last complete/join/violation cannot pass just
because no subsequent raw arrived. A terminal stream seal fixes final source
sequence, witness/observation counts and digests. Missing seals cannot support
a complete-recording claim. Pending requests in a declared prefix remain
pending, rather than being certified or automatically called a violation.

Each export ACK also requires its entire expected source span and sidecars
to match, even when protocol requests legitimately remain pending. A genuine
observer violation may be authenticated as observed failure, never as a
successful transaction; consumer integrity failures poison the lifetime stream
and cannot be cleared by a subsequent reset.

Repeated report calls are idempotent. Saved cursor/integrity state cannot
skip missing journal events. No clock or physical reset semantics are inferred
from an epoch integer alone.

## Bounds, saved evidence and replay

Use the admitted observer's explicit edge/byte/record/scope limits and explicit
consumer limits for stream/scope counts, raw mappings, witness queues, pending
joins, expected derived records, retained reports, input/record bytes and
journal gap. Sidecars/lifecycle/witness/seal rows count against Runner event
and evidence limits separately from the observer's max_records. Reserve one
bounded terminal failure record; test every limit at N-1/N/N+1. Streaming
maps retain active request references and bounded report witnesses; evicted
retired references cannot later be revived. Exhaustion produces a stable
refusal diagnostic before additional verification, never silent truncation
or a passing empty report. File-backed journals remain the complete source
history; do not scan all prior history on every drain.

Durable replay uses existing JSONL/zlib event views; EventJournal's temporary
pickle backing is not itself the durable recording. Repeated exports reuse
the saved journal/session/stream identities, never new UUIDs or wall time.
Durable replay loads a complete persisted journal with a trusted external
manifest/digest, artifact/contract and ordered stream bindings. Sidecar hashes
inside an attacker-rewritten journal alone are not authentication. Replay must
check original pin/record digest and projection consistency, not just that a
reference points to some row. Native nonces remain in raw evidence. First/fresh
semantic comparison may pair execution scopes only through an explicit
bijection established from actual process records; session identities are paired through their own
explicit bijection, and observer stream ordinals remain stable. Preserve all other scope,
stream ordinal, payload, refs and ordering fields. Save the exact comparison
rules and all raw originals. Original receipt/record/sidecar/seal digests are
validated independently in each run. In the semantic comparison view, recompute
identity-dependent digests from the paired normalized contents; never compare
nonce-dependent original digests as if they were invariant. Never replace
nonce-bearing raw evidence.

## Acceptance gates

1. Actual Runner import into list-backed and file-backed EventJournal, with
   interleaved unrelated events and per-sample producer clearing. Two renamed
   compatible instances prove dispatch and isolation without name branches.
2. AR/R, AW-before-W, W-before-AW, same-edge AW/W followed by a later B,
   and an old write B consumed before new AW/W on the same edge; stalls, IDs, lanes,
   native statuses and exact PRE-only acceptance; valid POST is not completion.
3. Reset with pending read, AW, W and joined write; end/begin scope, new
   testcase, native restart, monotonic lifetime indices and old-scope refusal.
4. Negative controls for missing/duplicate/forward references; reused names,
   wrong stream/session/contract/artifact; wrong types; changed pins/payloads;
   changed pending reset contexts; missing/reordered/extra source records or
   sidecars, including deletion of the final derived record; self-consistent
   rehashed counterfeit source records contradicted by issued receipts; budget
   exhaustion and failed export/append/ack. All must refuse verification.
5. Saved historical native receipts exercise software reprojection; record
   them as retrospective proof only. A new real native first/fresh run must
   separately prove actual import and semantic-prefix equality with distinct
   processes, pinned inputs and process exit receipts. Do not invent native
   wait/error/reset witnesses absent from the physical run.
6. Preserve OBI plural and AHB singular ownership/reporting regressions and
   existing Reduced AXI/DMA fixtures. Save failed and successful attempts,
   exact executed inputs, logs, resource receipts and independent reviews.
7. Update CURRENT_PROGRESS, LOCAL_HARNESS_RUNTIME, report/index and plan with
   the granted protocol boundary and every remaining full-system gate.

## Implementation boundaries

No RTL/profile/protocol role changes; no new complete AXI burst support.
No join to MemoryService writer/version, retirement, ISR, DMA effect or causal
feedback is granted. Such authority needs its own source-bound join and
acceptance. The source exporter, importer, sidecar format and observation
consumer must be designed and reviewed together; a passing mapping utility
alone does not fulfill this specification.
