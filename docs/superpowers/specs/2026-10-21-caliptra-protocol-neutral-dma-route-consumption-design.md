# Caliptra AHB-Lite Protocol-Neutral DMA Route Consumption

Date: 2026-10-21

## Goal

Use the existing protocol-neutral `DmaMasterRouteAdmission` on the real
Caliptra SHA256 AHB-Lite DMA path. This adds Caliptra as a third target protocol
consumer after PULP APB3 and ZipCPU Wishbone. D4 must match each native DMA
beat against the exact bound RAM-read or Caliptra CTRL-write route before the
existing Caliptra beat policy or target provider can observe it.

## Current inputs to reuse

- `DmaMasterRouteAdmission` already verifies the selected read/write route,
  typed transaction key, complete `DmaMasterRouteMatch`, and response-key
  association before delegating to a target-specific beat policy.
- `CaliptraSha256DmaBeatAdmission` already enforces one aligned RAM-word read,
  then a full-word `CTRL` write at offset `0x10` with value `5`, followed by
  successful typed service-completion callbacks. These callbacks are distinct
  from the later native Wishbone responses, which must be checked separately.
- `_caliptra_d4_declaration(...)` and the D4 binder already pin the Caliptra
  AHB artifact/provider and DMA endpoint links, bind the prepared graph, and
  return a `BoundDmaIntentTopology` route matcher.
- The existing opt-in native Caliptra gate already observes the RAM transfer,
  AHB write, SHA-256(`abc`) result, fresh replay, and in-window `CTRL+4`
  refusal. Those older results remain separate evidence; they do not prove
  D4 route consumption.

## Design

For each positive, fresh, and refusal execution, the native fixture will build
one `PreparedRuntimePathContract` for RAM-read to Caliptra CTRL-write. Its D2
route aperture, D3 wiring, shared `PersistentMemory`, and native RAM geometry
must agree exactly. The fixture will use a generated CPU artifact as the RAM
owner and the generated DMA artifact's endpoint-link evidence. It will pass
the D3 wiring and the same prepared object to the existing Caliptra D4
declaration/binder, which must bind that object exactly once.

After binding, the fixture will construct `CaliptraSha256DmaBeatAdmission` for
its existing one-word semantics, wrap it in `DmaMasterRouteAdmission` using
the exact bound `(0,0)` RAM-read and `(2,0)` Caliptra-write routes, and install
that shared gate on the DMA session. The old compile helper remains compatible
for its existing callers; the native D4 path uses the pure prepare API and
must not call a wrapper that binds or installs an admission a second time.

The positive and fresh executions must join the RAM-read route match to the
same transaction key's memory read and keyed service completion, then
independently join that key to the successful native Wishbone response. The
CTRL-write route match must join to the same key's DMA write, keyed AHB
provider receipt/request-data response, and keyed service completion; the
subsequent native Wishbone response must also be present under that key. The
native SHA status and digest remain higher-level behavior evidence. Fresh
normalized reference and replay records must be equal.

The refusal keeps the real in-window `CTRL+4` Wishbone request. Its RAM read
may already have been admitted; only the unselected write is refused. The
route-match record must therefore contain the RAM read only. The refusal must
be the exact D4 matcher failure,
`DMA route match does not exactly match the selected route`, and the policy
must remain in `expect_write`; otherwise a missing write route row could be
caused by the Caliptra policy or provider rejecting it instead. The provider
method and its sealed class implementation must remain untouched after D4
binding: the current provider-call counter replaces the instance method, which
the topology guard correctly treats as identity drift. Refusal evidence will
combine the pre-backend native request, the D4-specific refusal reason, policy
state, absence of a write route match and provider receipt, and unchanged AHB
local ticks. These observations show that the D4 route check stopped the
request before target access; they do not claim a direct provider-call
counter. The rejected DMA write must cause no RAM write or SHA target effect.
RAM preload and SHA block setup occur before the DMA request and are outside
this no-side-effect assertion.

## Geometry and compatibility constraints

- The Caliptra D2/D3 helper gains optional RAM base/size parameters while
  preserving the existing defaults and serialized route rows for current
  callers. The native fixture supplies its actual `RAM_BASE` and `RAM_SIZE`;
  ROM is placed outside that range.
- The generated CPU owner, DMA endpoint-link artifact, prepared route, runtime
  memory service, and live RAM use one exact resource identity and aperture.
- Each execution binds the same prepared object once. The D2/D3 route and
  target-template declarations stay unchanged; no D2/D3 DMA transfer edge is
  added and F6 stays `unsupported`.
- The D4 credential proves a software topology-bound route lookup. The shared
  admission does not replace Caliptra's AHB provider or beat policy and does
  not grant execution authority.

## Verification and evidence

The implementation plan will cover:

1. A focused Caliptra policy/shared-admission test for both exact route keys,
   response association, and refusal without policy-state or route-evidence
   mutation.
2. The existing D2/D3/D4 topology tests with default geometry preserved and a
   native-sized geometry case.
3. The opt-in native positive, independent fresh replay, and `CTRL+4` refusal,
   saved in a new Caliptra D4 route-consumption evidence directory rather than
   relabeling the prior attempt7 evidence.
4. A report and updates to current progress and report/plan indexes, with the
   route matches, key joins, bind-once proof, fresh equality, and limitations
   stated explicitly.

The exact gate commands and acceptance fields will be frozen in the
implementation plan after this spec review.

## Scope boundary

This is bounded single-word, process-level transaction composition between a
Wishbone DMA model and an AHB-Lite Caliptra target. It does not prove a physical
Wishbone-to-AHB bridge, CPU DMA programming or retirement, multiword DMA,
arbitrary AHB target support, F6 execution, P7-E onboarding, or completion of
P6/P7/P8 and the six-CPU/four-IP objective.
