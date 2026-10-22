# Next native exact-source completion slice — source design draft

Source analysis only; no production changes, imports, tests, runtime, audit or
remote operation. The actual six host bindings prove host input association;
they do not issue source-completion authority. This proposes the next separately
reviewed, default-disabled live producer.

## Actual current carrier and timing

`GeneratedNativeMemorySession._service_accepted_request` obtains the actual
immutable `ReadSnapshot` from `MemoryService.read`, calls
`NativeBusObserver.bind_read_snapshot(key, snapshot)` directly, then returns
snapshot.value. Session `_pending` is only `(response, memory_sequence)`; it
never carries the snapshot. Observer `pending` currently retains only the
asdict/hex projection. Therefore the smallest carrier change is inside observer
pending, alongside its existing projection: retain original snapshot identity,
original TransactionKey identity and actual service owner. Do not enlarge or
reinterpret session `_pending` as a source receipt.

The observer creates accepted pending before the session services that request.
On backend response consumption it validates the pending response and records
POST ready/rdata as an offer. Session then clears its backend `_pending`.
Observer still owns its outstanding transaction. Only next PRE valid&&ready,
stable marker/address/strobes and exact response tick+1/rdata qualify for
completion. The new hook belongs after all existing completion checks and before
observer pending is cleared. Failed response consumption, reset, abort, finish
with pending or a POST offer cannot enter this producer.

## Smallest implementation order and interfaces

1. **memory_service.py / memory.py, actual read issuance.** Preserve current
   read/event behavior. Add code-owned transient recognition of the actual
   successful original `MemoryService.read` return, exact owner memory/service,
   TransactionKey, snapshot identity and immutable material. Original method
   closure pins and original-frame checks must prevent a subclass override or
   caller constructing an equal ReadSnapshot from registering it. The read
   receipt may be registered only after the real service append succeeds; event
   append failure remains a real read without successful eligible service return.
   Keep this separate from instruction acceptance and write commit registries.
   A narrowly pinned original service-return frame handoff can replace an extra
   public receipt type, but equal dataclass/material validation alone cannot.
2. **native_session.py, original service handoff.** Only the existing original
   read call site may bind that actual return to this observer's exact accepted
   transaction, owner nonce/epoch and service. Pin the original caller/method
   once through closure anchors. No public arbitrary callback or user-supplied
   producer may install authority. No extra read, write, tick or response changes.
3. **native_cpu_events.py, actual completion hook.** Preserve raw schemas and
   existing projection. Retain the issued snapshot/reference token in pending;
   at validated next-PRE completion pass the actual pending object, actual
   command receipt, original key/snapshot, owner and native marker tuple to the
   dedicated producer. Producer verifies original observe completion frame and
   immutable context. Do not call from drain or reconstruct from samples.
4. **new native_instruction_bus_completion.py.** Frozen result plus closure-owned
   issuance registry keyed by actual object identities (owner weakref checked
   with `is`, not equality-key aliasing). It consumes the actual still-valid
   issued host binding from native_instruction_source_binding, not its published
   dictionary. Locate only bindings owned by this session/memory/nonce/epoch;
   compare all four exact admitted lanes and source/admission identity. Pins are
   bound once to original installed execution/service/observer functions.
5. **native_instruction_source_binding.py / session_runtime.py.** Add a private
   code-owned lookup/validation seam for active bindings by owner plus exact
   snapshot lanes, returning the original issued binding. Keep host event format
   and existing actual return identity/service-event checks. Reject multiple
   eligible bindings, stale/revoked tokens and post-finish access. Only the
   original opt-in install path may install the completion producer.
6. **runner.py.** Drain an already issued completion fact and publish detached
   references to original admission, service, host binding, raw accepted/
   response/completed samples and native completion projection. Raw/journal
   lookup assigns IDs; it never mints authority. A new narrow typed consumer
   must validate the issued original object before counting source consumption;
   an offline asdict/hash match cannot create that object.

## Exact eligibility and refusal

Require native instruction marker1 at accepted/response/completion, native
read strobes0, backend full BE15, aligned exact four-byte source address, one
actual modeled RAM read and matching full TransactionKey. Require snapshot
memory_id, byte_offset, generation, data, all versions, writer IDs and
INSTRUCTION_SOURCE kinds equal the host binding's actual acceptance. Require
owner/service/memory identity, current actual nonce/reset epoch, source action,
registered admission/case/path/direction and canonical full fragment unchanged.
ReadSnapshot carries actual kinds even though this gate's service journal omits
them; no inferred or synthesized service field is allowed.

A data read of the same bytes, marker0, MMIO/no snapshot, source/support NOP,
bootstrap, mixed writer/version, partial word, address alias without matching
resolved span, substituted transaction/owner, old generation or caller-created
receipt refuses. Preserve the distinction between an unrelated instruction
transfer (no eligible fuzz binding, diagnostic-only) and a contradictory
selected-source candidate (poison/refuse); otherwise bootstrap traffic would
break enabled sessions. Define that candidate predicate before implementation.

Deduplicate by full owner/epoch/transaction/accepted-response-completion scope.
Repeated publication of one completion refuses. A new actual refetch may issue
a distinct transfer fact for the same active binding; novelty/feedback credit
is outside this slice and must not be implied by multiplicity.

## Opt-in, lifecycle and fresh scope

Use a separate strict bool `native_source_completion=False`, requiring existing
native completion observation and source binding. Thread it through native
runtime/packet factory, immutable policy/manifest, exported plan and guarded
fresh factory; saved true versus supplied false, absent schema or changed bounds
must refuse before startup. Give the new policy/event an explicit schema version
and add its module to a new explicit HARNESS V2 identity (V1 stays34). Do not
silently reinterpret schema20/21 or historical70-path passes as new validation.

Reset cancels snapshot/transfer eligibility and revokes old-epoch grants. Abort
poisons once and performs original cleanup while preserving primary failure.
Normal finish revokes live handles only after real quiesce drains outstanding
completion; no synthetic completion/tick. Hook failure after actual hardware
progress records that prefix, poisons eligibility and closes once. Release
transient read references on completion/reset/abort to avoid retaining history.
Base/Deferred paths and fresh owner install must enforce identical scope.

Fresh must execute the entire saved warmup/cases/finish with independent real
owners and new nonce. Raw remains unchanged. Normalize only known new schema's
explicit owned execution scopes after independently validating raw references;
compare all other fields/events/status/ticks. No live binding or completion token
crosses into fresh execution from saved documents.

## Intended result and exclusions

Proposed receipt `native_instruction_bus_completion.v1`, proof scope
`native_instruction_bus_transfer_completed`, records exact admitted word's actual
instruction-bus completion. Initially publish with authority grants false until
the dedicated issued-object consumer and a new independent actual gate qualify
the exact boundary. Do not reuse `_InstructionEvidence`, broaden frozen Ibex
certificates, or infer decode/execution/architectural retirement, GPIO/IP payload
consumption or feedback from the transfer. Retirement and feedback are not part
of this implementation slice. Root design review must settle candidate mismatch
policy and the versioned consumer before production implementation.
