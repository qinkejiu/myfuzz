# Native observation identity comparison projection

Status: source-only helper; not connected to full replay. No runtime result,
source authority, RFuzz acceptance or P6 completion is granted.

The new `scenario/native_replay_identity.py` copies complete events and changes
only declared native observation process identity fields. It requires an
explicit component, reset epoch and actual process UUID from an owned session;
it never learns an allowed identity from the first event. This first helper
supports one reset epoch, matching packet sessions that prohibit resets.

The only rewrite sites are `local_tick_sample.native_driver_scope.execution`
and the three `native_bus_observation.v1` event kinds' top-level execution and
completion accepted/response scope execution. Scope keys, types, epoch, UUID,
local tick, raw producer event reference and prior accepted/response scopes are
checked before substitution. Completion response is required to precede its
native completion by exactly one local tick. Unknown scope identities refuse.
Arbitrary payload strings and all signal, transaction, snapshot, writer, phase,
command sequence and tick fields remain unchanged. Original journal objects
are never modified. The helper does not attest that a supplied owner UUID is
live; that binding belongs to the trusted replay call site.

Full replay wiring must still obtain identities from actual original/fresh
sessions, validate each original raw semantic hash, compare the entire projected
trace including status/ticks, and retain both unmodified raw hashes and journals.
No semantic equality check may simply be dropped to accommodate changed nonces.
The new live dependency must be added to the appropriate host source closure
when wired. Standalone packet document/max_cases binding remains separate.

Static AST parsing and whitespace inspection only. No project imports, tests,
builds, models, frontend queries or remote commands were executed. Independent
source review found the actual Runner raw/projection field shapes consistent
and no Important issue within this helper scope. Old frozen native evidence
does not validate this code.

## Full replay source wiring

The explicit native runtime now supplies the actual original CPU owner's
execution nonce. Fresh replay requires its own exact NativeBusObserver owner,
healthy and without an unfinished transfer, epoch0 and a distinct process nonce.
Each side's unmodified full raw semantic hash is recomputed before comparison.
The whole projected events/status/ticks payload is compared semantically;
manifest, plan, schedules, admissions and terminal checks remain in force.
Returned actual traces retain original fresh nonces and raw hashes. Legacy
callers with no native reference identity keep exact original comparison.
HARNESS v2 now explicitly includes the comparison module (69 paths); HOST v1
is unchanged. The guarded fresh cleanup correction also received independent
source review, closing its earlier process cleanup finding.

Independent review of this wiring found no new Important issue. Static AST and
whitespace checks only; no tests, imports, models or remote gate were run.
Packet persisted-document/max_cases binding, terminal failure serialization,
exact source joins, native gate metrics and new actual gate remain open.
