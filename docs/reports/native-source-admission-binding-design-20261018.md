# Native source admission to actual acceptance: next C2 design

Design only, following the reviewed memory-issuance increment `9e0666f`.
No implementation, project imports, tests, models or remote execution were
performed. A bound acceptance would still be a host-input fact, not a native
bus completion or source-consumption capability.

## Existing execution and eligibility

`ScenarioSession.configure_runtime_paths` enables provenance by default.
`submit_case` resolves the selected runtime source/path, validates the case,
requires unique action IDs, records the attempted case/source role, and makes
SourceAdmissions through `_case_admissions`. `_execute_case` first registers
those admissions, then accepts support instructions, then accepts the selected
instruction or injects the selected pin input, and only then advances clocks.
Keep that order and the single actual acceptance call for each fragment.

`GeneratedNativeMemorySession.accept_instructions` currently drops the new
MemoryService return value. It must return the actual successful result for the
new seam. No new instruction acceptance or RAM read is necessary. The service
already validates the original issued result and returns it only after its
existing instruction_source event append succeeds. A retained memory issuance
after an event-append failure must not be bound as a successful service result.

These paths are distinct:

| Actual path | Proposed selected-source binding |
| --- | --- |
| Initial images in ScenarioSession.begin, including native bootstrap and immutable packet tails | None; preload is not this acceptance path |
| advance_initial warmup | None; it advances existing state without a new admitted instruction input |
| Selected OnlineInstruction with source_role=fuzz_source | Eligible only after exact registered admission and actual acceptance join |
| Selected OnlineInstruction with source_role=bootstrap | Not eligible for fuzz-source binding |
| case.support_instructions | Fixed-support admission; never eligible, including the IP case's NOP |
| BatchSourceEvent pin source | Requires a future independent pin producer; its instruction support is not that source |

Never infer eligibility from INSTRUCTION_SOURCE memory kind, NOP opcode,
current case, or an action-ID substring. Exact registered role/input-kind and
selected source identity are necessary.

## Minimal typed seam and file sequence

1. `local_harness/native_session.py`: propagate the exact successful service
   InstructionAcceptance return. Keep the method's existing slot checks and
   actual service call. Native-only code/source/owner pinning must distinguish
   the selected producer from other protocols inheriting this class.
2. New `scenario/native_instruction_source_binding.py`: define a frozen
   `NativeInstructionSourceBinding` with admission identity/material, exact
   full fragment, actual memory-acceptance reference, memory ID/offset/version,
   actual ScenarioSession/runner/native owner identity and process nonce/epoch.
   Object owners may stay in a private registry while the public frozen record
   carries detached scope data. No CPU fetch/completion/source grant fields.
3. `scenario/session_runtime.py`, `_execute_case`: after the selected
   OnlineInstruction accept call returns, invoke only the installed code-owned
   native binder with that actual result, exact selected OnlineInstruction,
   case/index, role and already registered admission. Do not bind in the support
   loop or pin-injection branch. Bind before the first advance, within the
   existing actual-operation exception handling. Explicit opt-in admission
   selects the original producer, not an arbitrary caller callback/capability
   string. Legacy sessions retain their existing accept return behavior.
4. Native assembly enables that binder before begin, requiring provenance,
   original native producer/observer and the existing fixed packet policy for
   the first bounded increment. `NativePacketSession` continues using inherited
   `_execute_case`; avoid a second acceptance/registration implementation in
   its submit wrapper. Persisted configuration/host identity/fresh factory
   binding must be added when this opt-in is implemented, rather than silently
   enabling stronger behavior from an unchanged replay manifest.

An indicative internal operation is
`bind_actual_selected_instruction(session, case, case_index, admission, acceptance)`.
Its arguments are not authority by themselves. It is callable only from the
original actual execution frame and validates its installed owner/method pins.
A public deserialize/create method must not mint an issued binding.

## Exact joins and one-time issuance

Require the runner registry's original SourceAdmission for the selected action;
check case ID/index, selected source/path/direction/component, role fuzz_source,
input_kind instruction and exact action ID. Recompute input_sha256 from canonical
`{**asdict(OnlineInstruction), kind: instruction}` using the established canonical
encoding; a byte-only hash is different. Compare the exact fragment address and
all bytes to the original memory-issued acceptance, plus writer IDs/kinds,
generation/versions and resolved span. Validate the original acceptance through
the captured memory issuer, not equality with a caller-built dataclass.

Require the same actual session, runner, native CPU owner, memory, process
nonce/epoch and active attempted case that executed the service call. Preserve
the successful service-call/event relationship using an owned receipt/reference
or original call-frame token; do not search later journal dictionaries for a
matching instruction_source row and treat that as live origin. Later mutation
of that row cannot change frozen binding material.

Keep closure-owned registries keyed by owner ID plus checked weak-reference
identity; WeakKeyDictionary equality alone permits owner aliasing. Capture
producer methods/code in a one-shot closure bind, and validate resolved methods
before dispatch. Register each actual acceptance object once under one action/
admission/case. Retain original binding identity and immutable material;
same-object rebind, same action with different acceptance, copied/equal token,
foreign owner or changed producer is refused. Reading/validating an existing
issued binding is separate from issuing it again. Bound caller objects or
saved JSON can never establish live registry membership.

## Multiword input, cache and failure behavior

ScenarioSession and PersistentMemory accept whole multiword fragments. The
actual acceptance records every byte/lane, and a generic binding must compare
the full fragment and its full canonical admission document. Do not truncate
it to four bytes. NativePacketSession separately requires a four-byte selected
word; its support path remains fixed NOP only. A future native fetch producer
may select an exact four-lane slice by actual fetch address within an issued
fragment, while retaining the full original admission identity and offset.

Successful duplicate case IDs return the existing base receipt before entering
`_execute_case`; no write, bind, event or cursor increment occurs. The binder
must not run on this cache path. NativePacketSession checks terminal state
before its duplicate-cache path, preventing a failed physical case from
reviving. Do not change decoder commit ownership. Post-submit decoder commit
failure remains terminal through the existing failure notification.

A bind failure occurs after a real host write; preserve the attempted case,
halt the session and perform original once-only cleanup, with the first
exception retained. Do not call it a pure candidate rejection or roll back
RAM. Reset/abort/close revoke or poison bindings according to their scope;
warm reset cannot let a preserved memory word authenticate a new process.
No event-append-failed issuance, support NOP, initial image, replayed token or
offline reconstruction obtains the proposed binding.

The observer's later exact-byte native completion hook, live result issuance,
software mutation controls and new actual exact-source gate remain separate
unimplemented work. Existing native transfer and metadata results do not
validate this design or its eventual code.
