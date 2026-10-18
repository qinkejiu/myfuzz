# Minimal native exact-source completion design

Source-only proposal after reading NativeBusObserver, ReadSnapshot,
MemoryService, source admission/provenance and RFuzz instruction evidence.
No implementation, imports, tests, models or remote execution were performed.

## Proposed narrow producer

Add a separately versioned code-owned live producer for
`native_instruction_bus_completion.v1`, capability
`instruction_bus_completion.native_memory.v1`, with scope
`native_instruction_bus_transfer_completed` and `retirement_observed=false`.
Keep the current transfer-only events and existing Ibex certificates unchanged.
A saved-data checker may reproduce diagnostics but cannot issue live tokens.

The producer must join two actual owned hooks: successful source acceptance
and the observer's verified next-PRE native completion. Attach it through
explicit native opt-in assembly and validated original producer methods;
arbitrary caller dictionaries/callbacks are not admission authority. The live
completion hook should receive the immutable actual snapshot/current transaction
before observer state is discarded, rather than parse Runner event dictionaries
back into live authority. Runner may later attach event references to the same
owned fact when it publishes the real raw frame.

SourceAcceptance must retain the exact immutable four-byte OnlineInstruction,
its registered SourceAdmission, resolved memory address/offset, generation and
actual write version from successful accept_instructions. The current admission
hash is SHA256 of canonical `{**asdict(action), kind: instruction}`, not SHA256
of bytes alone (`session_runtime.py`, `_case_admissions`). Recompute that exact
document; carry a separate byte digest if useful. Registry membership alone is
not evidence of successful RAM acceptance. The acceptance hook must run after
the existing memory write succeeds, without another RAM read or CPU tick.
Memory currently installs one version across all admitted bytes but returns no
acceptance receipt; exposing a frozen actual acceptance result is the narrow
additional seam if exact admitted-version binding is required.

On native completion require marker1, read wstrb0, exact aligned source address,
full backend BE15 and the existing accepted-request/response/native-handshake
join. Use the actual ReadSnapshot already bound by service: all four data bytes
equal the source word; all four writer IDs equal the action; all four kinds
are INSTRUCTION_SOURCE; versions and generation equal the recorded successful
acceptance; transaction, memory identity/offset and current epoch/process match.
Snapshot.writer_kinds is always populated even when MemoryService's optional
memory_read journal field is disabled. Do not infer a missing kind from an ID.
Keep all native transactions in the sequence, including data/MMIO.

The immutable receipt should contain producer/source/artifact binding, admitted
action/admission/source/path/case IDs, source bytes/address, full transaction,
actual acceptance version, four-lane snapshot, accepted/response/completed
scopes and real raw event references. Deduplicate by full transfer identity;
same receipt ID with changed evidence is terminal. A fetched source can be
re-read in another real transaction, while feedback novelty remains separately
deduplicated by its defined feature identity.

## Required refusal boundaries

Refuse source authority for marker0 data reads, writes, MMIO/no snapshot,
fixed_support/bootstrap roles, NOP support actions, unknown/mismatched admission,
unaccepted source writes, wrong address/component/path, partial/mixed writers,
one bad byte/kind/version/generation, replaced producer, missing raw taps,
response mismatch/error, duplicate/gapped/out-of-order scope, reset cancellation,
close before native completion or any poisoned observer. Ordinary support/data
transactions may retain their current transfer diagnostics. A selected IP
source's support NOP cannot certify that IP payload.

Do not widen `_InstructionEvidence` channel `instr` to arbitrary `memory`, or
reuse its downstream/energy claims: the new receipt proves an exact admitted
instruction word crossed the native instruction bus, without proving decode,
retirement, architectural effect, IRQ, GPIO payload consumption or closed loop.
Enable only a separately registered narrow consumer after independent source
review, software mutation controls and an actual newly frozen native gate.
