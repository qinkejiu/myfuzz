# Native exact-source join: minimal implementation seams

Source review only. This document proposes the next C2 increment; none of the
hooks below are implemented or validated by this document. No project imports,
tests, models, Git child execution or remote operations were performed.
The accepted native transfer observation does not grant exact-source authority.

## Implementation order and owned boundaries

1. `scenario/memory.py`, `PersistentMemory.accept_instructions`: after the
   existing successful byte writes, return a frozen acceptance result recording
   memory identity, resolved offset/address, generation, actual allocated
   version, exact four bytes and action ID. The current method already assigns
   one actual version and INSTRUCTION_SOURCE kind to all admitted bytes, but
   returns no receipt. Do not add a RAM read, clock or alternate write path.
   Preserve support for existing callers/fragments; the new source producer
   explicitly admits only its four-byte native packet subset.
2. `scenario/memory_service.py`, `MemoryService.accept_instructions`: propagate
   that actual result after the original memory call succeeds. Preserve the
   existing instruction_source journal meaning; its current generation/data
   fields alone do not prove a successful exact-version source join.
3. `scenario/session_runtime.py`, `_execute_case`: retain the actual order of
   SourceAdmission registration, support acceptance and selected-source
   acceptance. Bind the successful acceptance to the exact OnlineInstruction
   through a code-owned, opt-in native seam. Obtain the admission from this
   runner's registered provenance, with the actual selected path/source/case.
   `_case_admissions` hashes canonical `{**asdict(action), kind: instruction}`;
   this is not a hash of instruction bytes alone. Recompute that precise input
   document. Fixed support and bootstrap remain ineligible for fuzz-source
   authority even if their memory writer kind is INSTRUCTION_SOURCE.
4. `local_harness/native_session.py`, `accept_instructions`: retain the actual
   acceptance result from its existing service and bind it to the original
   session, memory and current process scope. Ordinary caller-supplied objects
   cannot register a successful write. Require completed native observer
   admission and explicit source-producer opt-in; default sessions retain
   their current behavior. Deferred inherits this acceptance path.
5. `scenario/native_cpu_events.py`, `bind_read_snapshot` and completion branch:
   keep a private reference to the actual immutable ReadSnapshot alongside its
   existing JSON projection. At the already validated next-PRE valid/ready
   handshake, invoke the dedicated source producer before clearing pending.
   Pass the actual current transaction, snapshot and verified completion
   context. Do not reconstruct a live receipt from Runner dictionaries or from
   the observer's current asdict(snapshot) projection.
6. New `scenario/native_instruction_bus_completion.py`: own the separately
   versioned producer, immutable live result and issued-result registry.
   Require marker1, read strobes0, backend BE15, exact aligned admitted address,
   same full memory transaction, nonce/epoch and actual acceptance/response/
   next-PRE order. All four snapshot bytes, writer IDs, INSTRUCTION_SOURCE
   kinds, generations and versions must match the successful admission.
7. `scenario/runner.py`: publish the owned fact with actual journal/raw event
   references. Publication assigns references; it cannot create a successful
   source fact. Install a separately versioned narrow consumer later, after
   independent review and validation. Preserve the existing instr-channel
   `_InstructionEvidence` and frozen Ibex certificates.

## Issuance and failure requirements

A frozen dataclass, matching dictionary, valid hash or registry admission is
not sufficient live origin. The producer must recognize an acceptance issued
by the actual memory/service invocation, privately registered to the original
owner/memory/process and exact result identity. Bind it once to the registered
action and compare its immutable material on every use. Do not permit a public
factory, caller callback or replacement method to establish the baseline.
Use code/source/artifact method pins and an owned issued registry, following
the project's existing authority patterns. Saved-data reducers remain purely
diagnostic and cannot issue these live objects.

Deduplicate by full completed transfer identity. Same ID with different
material, foreign owner/epoch, reused acceptance under another action, changed
producer, mismatched lane or incomplete/failed command is a refusal. A later
real refetch may have a new transfer identity; feedback novelty needs its own
separately specified deduplication. Reset cancels pending joins, abort poisons
issuance, and normal close cannot turn an incomplete transfer into completion.
New failures must preserve the primary exception and actual prefix while
performing original once-only cleanup in base and Deferred paths.

## Remaining limits

Current ReadSnapshot always contains writer_kinds, even when MemoryService's
optional memory_read journal field is absent. Read the actual immutable
snapshot; do not infer kinds from writer IDs or fill missing service evidence.
Data reads, MMIO/no snapshot, support NOPs, mixed writers, partial/mismatched
bytes and unaccepted source attempts cannot obtain this capability.

Proposed schema is `native_instruction_bus_completion.v1`, capability
`instruction_bus_completion.native_memory.v1`, proof scope
`native_instruction_bus_transfer_completed`, with retirement_observed=false.
It establishes only that the exact admitted instruction word completed its
native instruction-bus transfer. Decode, execution, architectural retirement,
GPIO payload consumption, IRQ, four-feedback energy and closed-loop authority
remain separate. No implementation, new software controls, replay schema
integration or new actual exact-source gate is provided here.
