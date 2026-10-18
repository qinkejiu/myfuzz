# Closed native source-binding seam: source increment

Source increment independently reviewed within the closed seam scope. No project imports, tests,
models, builds or remote operations were performed. This is not C2 completion.

`GeneratedNativeMemorySession.accept_instructions` now returns the exact
successful MemoryService result. Its slot check, service call and event meaning
are unchanged. Inherited callers may ignore this additive return value.

New `native_instruction_source_binding.py` defines a frozen typed host-input
binding and closure-owned issuance registry. Original execution/native/service/
memory/admission method and code pins are captured once, before installation.
The private one-shot installer accepts no callback or caller-selected method:
it requires the actual original ScenarioSession._execute_case caller frame
on a NativePacketSession. Bind requires the same actual execution origin and
an installed owner. Current _execute_case contains neither call, and assembly
has no new opt-in, so ordinary callers cannot install or mint bindings. This
unconnected module is not a registered producer capability.

The implemented binding checks require the latest attempted selected
OnlineInstruction case, selected role fuzz_source, the registry's original
SourceAdmission object, exact case/index/source/path/direction/component/action
and the established canonical full OnlineInstruction document hash. The actual
dataclass contains data_hex; data is a property, not an asdict bytes field.
Binding material converts only actual acceptance.data to hex for canonical
storage, retaining the original source material. The full fragment is matched
without truncation; each aligned four-byte span is resolved against actual
memory identity/generation/offset. Fixed support, selected bootstrap roles and
pin-source cases refuse the selected-instruction binder.

The acceptance must be the original memory-issued identity with unchanged
material and all matching byte/writer/kind/version lanes. The active native
owner requires its original bound accept method and actual service/memory
identity, native artifact kind, original observer owner and observed execution/
epoch, plus a live process. The first bounded scope requires exact
PersistentMemory/MemoryService and NativePacketSession types. Original
GeneratedNativeMemorySession.accept_instructions and its inherited Deferred
path remain the supported native acceptance origin; other protocols refuse.

Registry owners use ID plus checked weak-reference identity. A session installs
once and cannot reinstall after revoke. An acceptance or action binds once;
original issued binding identity plus frozen canonical material is needed for
validation. Equal/copy dataclasses, foreign owners, changed producers, changed
nonce/epoch or inactive/finished/failed session refuse. Explicit failure-only
revocation is available. Current lifecycle hooks do not call it; the active
session/process checks independently invalidate closed/reset contexts.

The future actual execution hook must pass the returned result of its exact
successful native service invocation, after that invocation's event append.
The current original native/service dispatch enforces that return ordering;
memory issuance alone does not prove successful service return. No later
search for a matching instruction_source dictionary can mint a live binding.
Successful case-cache retries must continue bypassing this issuance path, and
future post-write bind errors must retain the actual prefix and trigger the
existing terminal cleanup rather than become pure candidate rejection.

Not implemented: _execute_case hook, assembly opt-in, persisted policy/host
manifest closure, fresh factory/replay configuration, lifecycle registration,
binding journal publication, observer exact native bus completion join,
consumer capability, software controls or a new actual gate. The new module
does not enter the current host source identity until that integration is
explicitly implemented. No retirement, source-consumption, feedback, GPIO or
closed-loop authority is granted; frozen Ibex certificates remain untouched.

Independent source review found no new Critical/Important findings. Reviewed native_session.py SHA256 `4077c26ff5b3d8e472f5beda5c7b82e32bb419f576e321e3ac52ce57b7b02fef`; new binding module `935c6b042e14d1921b23955e1001de13494c50716013cea3f1cd0d7b0bd004a7`. Root independently rehashed both files. No execution coverage or live-binding grant follows from this review.
