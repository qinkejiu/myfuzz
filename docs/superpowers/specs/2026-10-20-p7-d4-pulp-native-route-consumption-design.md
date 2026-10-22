# P7 D4 PULP APB3 Native Route Consumption Design

Date: 2026-10-20

## Goal

Make the existing PULP GPIO APB3 D4 topology credential part of the real native
DMA path. A successful generated DMA case must consume the exact D4-bound RAM
read route and PADOUT write route before either target is observed, then join
each accepted beat to its own target activity and native response.

## Scope and architecture

Split `compile_pulp_gpio_dma_runtime_paths(...)` into a pure preparation API
`prepare_pulp_gpio_dma_runtime_paths(...)` and the existing convenience compile
API. Preparation creates the same graph, contract, prepared object, source
binding, and beat policy, but does not bind a runner or install an admission.
The compile API calls preparation, binds that exact `PreparedRuntimePathContract`
once, installs the existing beat admission, and returns the same externally
bound result as before.

The D4 native runner prepares the typed PULP graph and a matching D2/D3 route
declaration, replaces its placeholder CPU record with an exact generated local
artifact owner that shares the DMA memory, and binds D4 against the same
prepared object and live generated GPIO provider. Its installed route admission
combines the existing single-word ordering/data check with D4 route lookup. For
each accepted RAM read it matches the read route as persistent-memory access;
for each accepted PADOUT write it matches the APB3 peripheral route. Both
lookups use the exact accepted request's `TransactionKey`, address, operation,
byte enable, and write value. No route match means refusal before memory or
GPIO provider dispatch.

Use the existing D4 topology guard and admission identity pin. The composite
admission identity includes the D4 binding identity and the existing one-word
beat-policy identity. Its per-case observations retain detached route-match
documents keyed by `TransactionKey`; `begin_case` clears them and resets the
single-word state. It does not issue a runtime-transfer credential and does not
replace the native event ledger.

## Transaction and effect joins

The RAM read and PADOUT write are distinct native DMA beats and therefore have
distinct `TransactionKey` values. Evidence must join the read key to exactly
one MemoryService read and exactly one native read response (`rdata` equals the
source word and `error == 0`). The write key must join to exactly one PULP
target-provider receipt/APB3 effect and exactly one native write response
(`error == 0`). The single-word admission additionally requires the PADOUT
write value to equal the successful read response. Fresh replay compares the
normalized route matches, RAM data, APB3 effect, responses, and D4 binding
identity while allowing execution IDs to differ.

The existing wrong-offset native request remains a negative gate: D4 route
matching and beat admission refuse it before provider dispatch, with no APB3
access or PADOUT change. It must not be accepted merely because the request
falls inside the broader GPIO address aperture.

## Compatibility and refusal behavior

Keep the current `compile_pulp_gpio_dma_runtime_paths(...)` call behavior for
existing users. A second bind or a preinstalled admission remains an error.
Preparation rejects malformed RAM/GPIO windows and unsupported provider
identity before runner startup. D4 binds only after generated artifact,
endpoint-link, D2/D3 template, target-window, and prepared-graph checks pass.
Route lookup rejects wrong operation, target, address, byte enable, write value,
path, or transaction identity before target dispatch. Session reset/new case
clears pending one-word and route-match state.

The D4 credential remains `topology_bound`. F6 remains `unsupported`. This
slice does not claim a physical Wishbone-to-APB bridge, CPU DMA programming or
retirement, multiple-word DMA, generic F6, remote verification, or completion
of the six-CPU/four-IP program.

## Verification

Software tests must prove preparation has no bind/admission side effect; the
compatibility compile API binds once and installs one admission; and the real
positive native case binds D4 once against the same prepared object. The native
gate must assert both route matches, the separate read/write transaction joins,
RAM value propagation to PADOUT, zero-error native responses, and independent
fresh replay. The wrong-offset gate must observe the native request and prove
refusal before GPIO provider/APB3 effect. Existing D2/D3 route rows and F6
unsupported status remain unchanged.

## Implementation evidence

Implemented and verified on 2026-10-21. See the
[native route-consumption report](../../reports/p7-d4-pulp-native-route-consumption-20261021.md)
for the exact native/software gate results, transaction joins, fresh comparison,
and remaining scope limits.
