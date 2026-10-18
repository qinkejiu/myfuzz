# Native source-binding opt-in: concrete next integration

Design only after closed seam `44ce100`. No implementation, imports, tests,
models or remote execution. The next increment must actually connect the
service-return path, persisted configuration and fresh replay before a new gate;
host acceptance binding still grants no instruction-bus/source-consumption proof.

## Configuration and persisted contract

Add strict bool `native_source_binding=False` to NativePacketSession and the
native runtime constructor. True requires native_completion_observation=True,
configured provenance/runtime paths, the original native/service/memory
producers, and the existing four-byte packet policy. Reject unsupported
configuration before begin/input. False retains the current path.

Use a closed configuration document:

```
schema_version: native_packet_source_binding.v1
enabled: true
max_cases: <strict integer 1..96>
packet_policy: native_online_packet.v1
instruction_start: 512
instruction_end: 3584
stride_bytes: 32
source_binding_schema: native_instruction_source_binding.v1
native_completion_observation_required: true
proof_scope: host_instruction_input_bound
grants_source_consumption: false
grants_retirement: false
```

Freeze canonical configuration in the session before begin. The same document
belongs in `_online_manifest` and encoded plan; do not rely on max_cases supplied
only by the replay caller. Proposed new native-only success/failure schemas
20/21 carry exact base plan fields plus runtime_paths, provenance_configuration,
source_admissions and native_packet_configuration; 21 also carries existing
terminal_failure. Reserve/validate these explicitly against current 4..19
dispatch. Preserve old schema behavior. Reject register/reset or conflicting
native caller configuration; validate fixed bootstrap, all 97 reservations,
case bound and packet configuration before runner factory invocation.

Add native_instruction_source_binding.py to HARNESS_HOST_SOURCE_PATHS only:
V2 explicit host list becomes70; HOST_SOURCE_PATHS/V1 remains34. Update any
copy/host-count controls separately; never relabel frozen69-path evidence.

## Actual execution hook and successful-return origin

1. NativePacketSession.submit_case retains its original pre-input boundary and
   calls inherited ScenarioSession.submit_case exactly once. Existing successful
   case-cache retries return before `_execute_case`; terminal check remains
   before cache. No write/bind/cursor movement occurs on those retries.
2. `_execute_case` retains registration of its exact generated admissions,
   support acceptance loop, then selected source acceptance or pin injection.
   Add no binder call to support, bootstrap-role, pin-injection or warmup paths.
3. For an enabled selected fuzz-source OnlineInstruction only, save the direct
   return of the original native accept call as actual_instruction_acceptance.
   Native accept now returns only after MemoryService's real write, issued
   validation and unchanged instruction_source event append succeed. If any
   of these raises, no bind call runs. Do not search events or pass a receipt
   selected from an older registry as a substitute for that returned object.
4. Still inside that original `_execute_case` frame and before its first
   advance, perform one-time installation if needed, then call the binder with
   this same local result, the selected case/index and its exact registered
   admission. Capture the installed state in code-owned registry; a session
   boolean alone cannot authorize it. No callback/method parameter is accepted.
5. Keep the phase as source_admission through acceptance/binding so existing
   attempted-prefix recording and post-effect error handling remain applicable.
   Optional diagnostic subphase can identify binding without inventing a clean
   candidate rejection. Only after binding succeeds enter the existing step
   phase and execute the unchanged 128 rounds.

Import the binding module lazily from the enabled execution branch or validated
configuration seam after session_runtime has finished defining its classes.
The module imports ScenarioSession/NativePacketSession; a new top-level import
from session_runtime would create a cycle. At that first import it captures the
new original `_execute_case` method/code. Never reset method pins per case or
accept a caller-supplied replacement as the baseline. Its existing actual-frame
guard now becomes reachable through this explicit code-owned call.

The generic receipt/binder compares the complete source fragment and canonical
OnlineInstruction document, including data_hex; NativePacketSession separately
enforces four bytes. Do not truncate generic fragments or infer selected source
identity from the support NOP's INSTRUCTION_SOURCE writer kind.

## Lifecycle, publication and fresh chain

NativePacketSession.abort_packet_submission must revoke bindings before its
existing once-only cleanup. Normal finish/finally cleanup also revokes; preserve
detached diagnostic material for export, not a live registry token. Native
packet reset remains refused; generic reset must explicitly revoke if later
supported, and current nonce/epoch/context checks continue failing stale tokens.
After-write binder failure is terminal; preserve the original exception,
attempted case, accepted host bytes and complete actual prefix. No RAM rollback,
new acceptance, reset or extra tick is allowed to repair it.

Publish one explicitly host-only binding diagnostic per newly bound selected
action. Preserve actual instruction_source/service reference when Runner drains
that original event; publication assigns journal references to the already
issued fact and cannot mint it from matching dictionaries. Keep source binding
and native transfer completion as separate event schemas. If nonce is exported,
extend typed fresh comparison solely for that new schema/known scope fields;
retain original raw events and compare every other field. Do not use generic
UUID substitution or the three-kind native-bus schema for this host-only fact.

`PicoNativeOnlineRuntime` passes the bool/max_cases into the original session;
the saved policy controls reconstruction. Fresh replay builds a new
NativePacketSession with exactly that policy before begin, retains all warmup,
cases and finish, and enables the original observation factory required by the
policy. Caller bool/max_cases mismatches refuse. Compare policy/manifest, full
plan, original raw semantic hashes and entire typed-normalized event prefix,
status/ticks/admissions/binding materials. Session constructors must validate
the actual fresh factory's native artifact/observer rather than trusting its
Python closure or a recorded capability string.

## Newly frozen directed gate

Add an explicit gate flag requiring the new policy. The existing positive
CPU/IP/CPU schedule should yield two selected CPU host bindings per original
and fresh run; the IP support NOP yields zero. The one-case controlled-response
run yields one binding per original/fresh. Thus expect six host bindings across
the four directed runs, with no bootstrap/tail/support binding. Validate every
actual acceptance/admission/fragment join, unchanged raw native transfer stream,
fresh identity distinction, complete replay and the original PADOUT XOR1 fault.

Source review and separately authorized software controls/new actual gate remain
required after implementation. This gate can qualify live host-input binding;
exact four-lane admission-to-native-completion joining, retirement, IP payload
consumption, feedback energy and closed-loop capability remain open.
