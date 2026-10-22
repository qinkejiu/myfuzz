# P7-C compiled F6 to D4 DMA handoff

Date: 2026-10-21
Status: implemented and verified as a bounded handoff; see the [result report](../../reports/p7-f6-compiled-dma-handoff-20261021.md).

## Decision

Carry the exact P7-C `compiled_paths.v1` F6 result into the existing D4 route
binding as explicit, digest-bound evidence. Keep P7-C static and incomplete:
the compiled F6 row must remain `unsupported` with
`dma-route-live-topology-binding-required`, and it must not contain a
`DMA_MASTER_TRANSFER` runtime edge. D4 then checks that this exact static route
set is the one linked bijectively to the already prepared live route graph,
binds that graph once to the actual Runner and generated endpoint links, and
leaves per-transaction admission to the existing `DmaMasterRouteAdmission`.

The first real consumer is the existing ZipCPU Wishbone DMA → Caliptra SHA256
AHB-Lite slice. This exercises the broadest target protocol already evidenced
while keeping the implementation to one end-to-end route pair.

## Why this slice

P7-B/P7-C already preserves route rows and their digests, and D4 already binds
those rows to generated endpoint links and a prepared runtime graph. However,
the Caliptra native fixture currently compiles D3, checks that F6 is
unsupported, then returns only `request.wiring`; D4 consumes that wiring but
does not receive or record the compiled result itself. This leaves a compiler
output-to-live-D4 lineage gap. P6 native CPU feedback and OpenTitan D4 are also
important next slices, but neither closes this common static-route-to-live-D4
handoff.

## Credential and APIs

Add `src/myfuzz/scenario/compiled_f6_dma_handoff.py` with two frozen wrappers:

```python
class CompiledF6DmaHandoffError(ValueError):
    code: str
    pointer: str

@dataclass(frozen=True)
class CompiledF6DmaHandoff:
    def document(self) -> dict: ...
    @property
    def identity_sha256(self) -> str: ...

def prepare_compiled_f6_dma_handoff(
        compiled_paths: Mapping[str, object], declaration
        ) -> CompiledF6DmaHandoff: ...

@dataclass(frozen=True)
class BoundCompiledF6DmaHandoff:
    def document(self) -> dict: ...
    @property
    def identity_sha256(self) -> str: ...
    def validate_topology(self) -> None: ...

def bind_compiled_f6_dma_handoff(
        handoff: CompiledF6DmaHandoff, runner, *, artifact_links
        ) -> BoundCompiledF6DmaHandoff: ...
```

The closed `compiled_f6_dma_handoff.v1` document contains:

- the complete `compiled_paths.v1` mapping and its canonical SHA256;
- the complete existing `PreparedDmaIntentBinding` document and its SHA256;
- the exact F6 `path_id`, `status`, refusal reason, and ordered route IDs;
- the wiring schema version, static route digest, and static binding digest;
- its own canonical identity SHA256.

The bound wrapper retains that document and the existing
`BoundDmaIntentTopology` credential in a closed
`bound_compiled_f6_dma_handoff.v1` document with exactly the keys
`schema_version`, `compiled_f6_handoff`, `topology_binding`, and
`identity_sha256`. It records the single prepared-graph bind and delegates
topology validation to the existing live guard. Readers reject unknown keys,
malformed containers, digest mismatch, route-set mismatch, a
non-F6 row, an F6 status/reason other than the required static refusal, or an
F6 runtime-path identity. The F6 route IDs and both wiring digests must match
the declaration's exact embedded wiring. No value is inferred from instance
names, filenames, addresses, route order, or the first master.

These digests establish the exact documents passed between the P7-C result and
D4 in the recorded process. They are not a compiler signature or an
independent proof that an arbitrary detached mapping was produced by P7-C.
The real gate therefore obtains `compiled_paths` directly from the same
`compile_paths(request)` call used to produce the `PathWiring` and records both
documents.

## Runtime rules

1. Static P7-C continues to report F6 as unsupported until live topology is
   bound; it emits no DMA transfer edge and no live identity hash.
2. D4 requires an exact one-to-one `route_id` to prepared typed-route mapping
   through existing `prepare_dma_intent_binding(...)` checks.
3. `bind_compiled_f6_dma_handoff(...)` invokes the existing topology binder on
   the same prepared object exactly once. It adds no runtime graph, memory,
   target provider, bridge, or new transaction semantics.
4. Every native request still passes through `DmaMasterRouteAdmission` before
   memory or peripheral dispatch. Existing target-specific beat policies remain
   responsible for target behavior.
5. Fresh execution reconstructs the D3 result from the same explicit request,
   checks the same handoff identity, and rebinds a newly created Runner before
   native startup. A mismatched compiled document refuses before provider
   effects.

## Alternatives considered

- **OpenTitan UART RX D4 route consumption:** adds the fourth IP family's
  target-specific evidence, but leaves the exact D3-output-to-D4 lineage gap
  and F6 runtime handoff open.
- **P6 native instruction completion / feedback:** directly advances CPU event
  expansion, but is a separate acceptance row with source-authority and
  consumer-feedback prerequisites. It does not close the present DMA compiler
  handoff.
- **Emit `DMA_MASTER_TRANSFER` directly in P7-C:** rejected for this slice.
  Static D2/D3 data has no live endpoint or target identities; manufacturing a
  runtime edge there would blur the established static/live authority boundary.

## Acceptance

- Unit cases accept the actual F6 compiler result only when it is the exact
  static refusal for the exact route and binding digests; they reject changed
  digests, a different route set, an executable/unknown F6 result, unknown
  schema fields, and an F6 runtime-path identity.
- D4 binding uses the exact prepared graph once, verifies artifact endpoint
  links and live target identities with the existing binder, and preserves the
  compiled handoff digest in saved evidence.
- The Caliptra native gate records a keyed positive RAM-read/CTRL-write run, an
  in-window wrong-route refusal before the target provider, and an independent
  fresh run with normalized equality. The compiled handoff identity must be
  equal in the original and fresh evidence.
- Existing P7-C refusal, D4 target-policy refusal, and route replay checks
  remain enforced. No new CPU configuration, CPU retirement, completion IRQ,
  physical Wishbone-to-AHB bridge, arbitrary F6, P7-E, or overall P6/P7/P8
  completion is claimed.
