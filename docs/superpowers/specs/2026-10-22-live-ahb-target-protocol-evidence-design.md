# Live AHB-Lite target protocol evidence design

## Goal and boundary

Connect an admitted generated AHB-Lite target's existing singular
`base_protocol_trace` to the Runner's bounded protocol evidence and L1 base
coverage report. The target already produces pre/post local tick receipts and
the Runner already projects AHB request, accept, wait, response, cancellation,
timeout and protocol-error events. This slice makes those existing events
available to the common report API without creating another journal or another
projection producer.

Reports remain `protocol_boundary_only`. A verified record means the declared
AHB boundary request/accept/response chain agrees with its raw pin samples. It
does not prove CPU origin, DMA functional effect, architectural consumption,
retirement, or a bug finding.

## Existing behavior

- CPU profiles with plural `base_protocol_traces` use
  `ProtocolTraceSetObserver` to authenticate and produce separate OBI endpoint
  projections, then report `IpProtocolEvidenceConsumer` certificates and
  `IpBaseCoverageConsumer` counters over the unchanged Runner journal.
- Generated targets such as `ahb_lite_register_observe` expose a singular
  `base_protocol_trace`; Runner already authenticates that trace when it builds
  its normalizer/checker and appends the resulting events to the same journal.
- The target's ordinary register session drains real pre/post tick samples,
  but does not set the CPU-only `_physical_tick_samples_enabled` flag.
- Consequently the current plural-only observer registration omits target
  protocol evidence and coverage. Reusing its projector would duplicate the
  target events already produced by Runner.

## Design

Extend `ProtocolTraceSetObserver` with two explicit modes:

1. **Plural producer-owned mode:** retain the existing authenticated CPU OBI
   trace-set path unchanged. It owns its normalizer/checker projection work.
2. **Singular Runner-owned mode:** accept one already admitted singular
   protocol trace only when Runner has an existing protocol normalizer and
   checker for that component and its session exposes `drain_tick_samples`.
   The observer owns only evidence/coverage state. Runner's existing projector
   and checker remain the only event producers.

Both modes consume the complete ordered Runner journal by its existing event
IDs. They keep one bounded evidence/coverage state per endpoint, use the
runtime artifact digest as the evidence contract identity, and expose the
existing `runner_protocol_trace_set_report.v1` API. The target path does not
rewrite raw events, filter other components, renumber events, or infer a native
AHB transaction ID; AHB's declared identity gap remains visible.

`IpBaseCoverageConsumer` will clear in-flight correlation state on the global
`reset_barrier`. It retains historical counters and epoch metadata; the
existing evidence consumer already clears pending chains at that barrier.

## Alternatives considered

- Add a separate target observer class: rejected because it would duplicate
  bounded cursor, evidence, coverage and report formatting logic.
- Attach the evidence and coverage consumers directly to every Runner tick:
  deferred because the established report consumer already replays an
  incremental journal prefix and exact report calls are idempotent. Online
  campaign feedback remains a separate P6 slice.

## Inputs, lifecycle, and failure behavior

The singular mode is enabled only after the standard Runner trace normalizer
and checker accept the generated artifact's protocol, endpoint, clock and wait
contract. Malformed or missing trace state fails closed during Runner
registration. Raw/projection mismatches remain diagnostics and do not issue a
verified certificate. Reset barriers clear pending coverage joins immediately;
historical counters/certificates remain available. Existing per-endpoint
bounds and journal-integrity checks remain in force.

## Acceptance and non-goals

Static acceptance for this source slice is: the existing plural CPU observer
still owns projection generation; singular target mode owns no projector;
Runner registers it only with the already admitted normalizer/checker and a
sample drain API; report replay consumes a complete unchanged journal prefix;
reset clears pending coverage without clearing accumulated counters.

A subsequent evidence gate should use saved or newly captured real AHB target
samples and verify request/accept/data response joins, wait/error/cancel
diagnostics, report cursor and reset lifecycle. This specification does not
claim that gate has run. No AHB CPU manager trace is adapted here: CVW's manager
boundary has a distinct authenticated `HREADYEXT`, internal ready and reset
mapping and must not be aliased to target `HREADYIN/HREADYOUT`.

No RTL, generated driver format, source profile, AHB DMA target policy, static
F6 result, CPU event schema, or physical bridge behavior changes in this slice.
