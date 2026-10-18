# Native online completion observation opt-in

Source-only integration adds keyword-only `native_completion_observation=False`
to the native online factory and runtime constructors. Both reject non-boolean
values before construction. The runtime forwards the choice to its retained
factory, so fresh runner construction uses the same artifact selection.

The CPU artifact helper switches the request document to `local_harness.v2`
only on explicit opt-in, with exactly one tuning record:
`raw_tick_stream: [{sampling: pre_post}]`. The existing strict request loader
constructs `LocalHarnessRequestV2`; the closed native physical observation
policy requires exactly that single record kind, and native completion contract
admission binds the actual native bus roles and instruction marker. No bus
roles, aliases or completion events are synthesized by these entry points.

Default construction retains its v1 request. GPIO construction still uses its
existing v1 request, wait16 and reset8/8. CPU retains wait1024 and reset8/8.
Packet reservations, source decoder, operation schedule, guard checks and
session creation are unchanged. Observation selection grants no instruction
source consumption, GPIO consumption, retirement or feedback authority.

Static self-review read request/tuning/native contract and observation policy
sources, parsed both changed modules with standard-library AST, confirmed all
new option defaults are literal False, and ran `git diff --check`. Source SHA256:

- `src/myfuzz/scenario/picorv32_native_online.py`: `ae7e6ae278881a92ad788aa7f19178a31525e4db8e803b15423ea0405562a8f0`
- `src/myfuzz/integration/picorv32_native_online.py`: `4d45cb92b7800e4efafccea88d766ed807a4a9189f8514d015bcf5ddb6bef28a`

No project import, tests, frontend/build/model, native process or remote command
was executed. This is source integration only: no new gate result exists and
no old actual pass is inherited by the changed source/artifact identity.
