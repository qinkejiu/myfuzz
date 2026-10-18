# Actual instruction acceptance: first C2 source increment

Source increment independently reviewed after both Important findings were fixed. No tests, project
imports, models, builds or remote operations were performed.

Owned production changes are confined to `scenario/memory.py` and
`scenario/memory_service.py`. PersistentMemory.accept_instructions retains its
existing validation, reservation, budget and byte-write path, then returns a
frozen InstructionAcceptance containing all actually accepted bytes, original
address/resolved offset, memory identity, generation and per-byte actual
writer ID/kind/version. Multiword fragments remain supported; the new receipt
does not restrict the established method to four bytes. Values accepted as
primitive subclasses by the existing method are normalized in the detached
receipt without changing the stored byte-write path.

A closure-owned registry records original receipt identity and its
strictly typed immutable material for each actual memory owner. Its owner key
uses id plus a weak reference checked with `is`, so custom equality/hash cannot
alias another memory and a recycled object ID cannot inherit an issuance.
Registration
checks that its caller is the original captured accept_instructions method
frame. Validation checks original issued object identity, unchanged material,
same current generation and original producer method/code. A caller-created
equal dataclass, copied receipt, foreign memory owner or modified receipt is
not an issued result. Warm and cold reset revoke issued identities; warm reset
still preserves existing committed bytes/generation. Registry lifetime follows
its memory owner, and no new live source capability is issued by this API.

MemoryService returns the original memory result only after checking issuance
through the code-owned PersistentMemory validator and appending its unchanged
instruction_source event. Existing callers may ignore the return value. There
is no extra RAM read/materialization, clock or service transaction. If the
event append fails after memory acceptance, the physical host write already
occurred and its memory issuance remains recorded, but the service raises and
does not return a successful result. This is not an atomic rollback; existing
session failure/cleanup rules must preserve that attempted prefix. Subsequent
producer integration must never infer completed source admission from registry
membership alone.

Independent review identified two origin gaps in the first draft. The producer
method/code pin now lives inside the registry closure and is bound once after
class definition; rebinding is refused. MemoryService now enters a code-owned
dispatch which verifies the owner's resolved method is that original bound
method, then invokes the captured actual write for this call. An override
returning an older genuine receipt cannot append a new successful service
event. Inherited subclasses without an override remain eligible. These are
source corrections awaiting independent follow-up; no tests were run.

The issuance records a host memory write only. It does not bind SourceAdmission,
path/case, native process/epoch/command, CPU-native request/response completion,
source-byte consumption, retirement, IRQ, energy or closed-loop authority.
No native session/observer/consumer hook or Ibex certificate was changed.
Source producer pin/registry binding and successful admission joining remain
the next separately reviewed increment. Existing gate results do not validate
these new bytes.

## Independent source review closure

The independent reviewer confirmed the producer-pin replacement and service override/replayed-receipt findings closed after correction. Reviewed `memory.py` SHA256 is `51d5bffec54cd4f57487d9d120b09a1917a6cef48cdefb8fb7333eb9cfee652f`; `memory_service.py` is `5e495f55035a73381ecfdec1c7afb622071a0a5fc2ac49988e7958f7f1fa6a35`. No new Critical/Important findings within this source scope. This is source review, with no execution/import/test or live grant.
