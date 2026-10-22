# Compiled F4 runtime path admission

Status: the user selected the bounded selected-F4 route (A) on 2026-10-22.
This bounded slice is implemented and accepted in two first/fresh native gates;
see the [report](../../reports/compiled-f4-runtime-path-admission-20261022.md).
General P7-E and system acceptance remain open.

## Goal and boundary

Bind the same-call D3 selected F4 dependency path to the actual online
`ScenarioSession` and its fresh replay. The session must configure and validate
the selected runtime contract before `begin()`, and every submitted compiled
instruction case must identify the runtime path that was admitted. The saved
run identity must let an auditor follow the D3 logical path, runtime graph
path, source image, CPU MMIO candidate and generated instruction fragment
through the first and fresh sessions.

This slice covers one selected F4 path. It does not claim general D3 execution,
retirement, CPU semantic consumption, generic CPU/IP admission, a built D2
harness identity, throughput acceptance, or full P7-E completion. F1-F3 and
F5-F6 remain outside this executor.

## Existing boundary

The compiled RFuzz caller already has the typed compile request, compiled D3
document, generated D2 artifacts and `compiled_inputs` in one execution call.
`CompiledF4Runtime` strictly re-admits those inputs and binds the selected F4
path into its own execution binding. It then creates a real `ScenarioSession`
and declares instruction slots, but begins the session without configuring a
`RuntimePathContract`. The compiled executor and decoder manifest therefore
report `runtime_path_status=legacy_unchecked`.

The identifiers and source types also differ across the bridge:

- D3 exposes a logical path ID such as `F4:ram.image`.
- The D3 runtime graph exposes the selected `F4.program_image` source as a
  `memory_image` and hashes its dependency path to a different runtime path
  ID.
- `CompiledOnlineDecoder` currently puts the logical D3 path ID in each
  `OnlineCase`, whose source is an `OnlineInstruction`.
- Generic online runtime validation currently resolves an
  `OnlineInstruction` only against a graph `instruction` source. It cannot
  resolve the selected F4 `memory_image` source.

The D3 F4 row also declares a CPU MMIO candidate source. It is projected by the
candidate layout and compiled into instruction bytes; it is not an independent
runtime graph leaf. Any extra selected F4 source that the adapter cannot map
must be refused before the session begins.

## Design

### Same-call typed admission

Add one strict F4 runtime-path admission helper used by the live constructor
and fresh replay. It consumes the exact `request`, `compiled` document, D2
artifacts, and ownership map already passed to `CompiledF4Runtime`; it does not
reload an alternate request or infer a path from names.

The helper will:

1. Re-run `compile_paths(request)` and require byte-semantic document equality
   with the supplied compiled D3 document.
2. Strictly load `runtime_dependency_graph` with
   `DependencyGraph.from_edge_document` and `runtime_path_contract` with
   `RuntimePathContract.from_document`; require the contract's graph digest to
   match the canonical loaded graph.
3. Require exactly one executable F4 row. Find the graph path whose
   `path_identity` equals the row's `runtime_path_identity.path_id`, and compare
   direction, source IDs and ordered edges field by field with that D3 row.
   The selected path must have the supported F4 target/edge shape and exactly
   one `memory_image` leaf.
4. Join the D3 `instruction_image` row to the graph leaf using exact component,
   resource/port, direction and bit width. Validate that the inclusive D3 image
   range has a positive byte length and that graph width equals that byte
   length in bits. No CPU/IP alias lookup is used.
5. Require the currently supported source shape: one instruction image and one
   CPU MMIO stream, with no unrepresented external pin or other source. Bind
   the stream's exact source ID and candidate-layout slice to the decoded
   register value, the generated instruction bytes, and the image source.
6. Produce a typed immutable binding containing the complete D3 document hash,
   selected D3 row hash, graph hash, runtime contract hash, logical and runtime
   path IDs, selected edge/source identities, image component/resource/range,
   CPU MMIO source/layout identity, D2 artifact identities, and ownership
   identity. Serialize this binding into the execution binding and compiled
   prefix.

The selected F4 runtime path ID, not the D3 display/logical ID, is used in
`OnlineCase.path_id`. Candidate and receipt documents retain both IDs and the
binding digest. This keeps online source admission aligned with the exact
runtime path while preserving the D3 logical identity for existing compiled
receipt joins.

The `OnlineInstruction` emitted by the compiled decoder will carry an explicit
runtime graph `source_id` through a versioned bound-instruction record. The
D3 logical image source ID and graph source ID remain separate fields in the
admission binding. The generic four-field `OnlineInstruction` form and its
serialized plans remain unchanged when no graph source ID is declared; replay
accepts the new field only in the versioned bound form.

### Range-bound source resolution

The generic runtime source resolver will gain a narrow, explicit bridge for a
`memory_image` graph source and an `OnlineInstruction` action. It accepts the
pair only when:

- the selected path contains exactly one declared memory-image source;
- component, resource/port, direction and image address are bound by the
  admitted F4 source binding;
- the D3 image's inclusive range is exactly the same resource and address
  span as one real `PersistentMemory` `MemoryRegion` on the bound CPU session
  (`base == range_start`, `size == range_end - range_start + 1`, and matching
  `memory_id`); graph width is `size * 8`;
- the instruction address is word-aligned and lies within the declared image
  range, and `address + len(data)` does not exceed the exclusive end;
- the bound instruction's explicit graph source ID equals the unique selected
  `memory_image` graph leaf, and its D3 source binding and candidate layout
  match the selected F4 instruction-image source and generated bytes; and
- the case uses the mapped runtime path ID.

The existing generic `instruction` source handling remains available for
existing `OnlineDependencyGraph` clients. An image source without an explicit
address/range binding cannot resolve an online instruction. Generic callers do
not receive an implicit source alias.

The static contract remains the existing D3 graph and contract. The adapter
does not rewrite the `memory_image` kind to `instruction`, mutate its graph
digest, or add an inferred edge for the MMIO candidate. The compiled F4
binding documents the explicit transformation from the MMIO candidate bytes
to the admitted instruction image.

Integration exposed a compiler declaration bug: F4's register-response target
was assigned to the CPU, contradicting its explicit CPU-to-peripheral MMIO
route. The D3 compiler will emit that F4 node and target metadata on the
declared target peripheral. New compilations and contract identities reflect
the correction; the runtime adapter still consumes the exact freshly compiled
graph/contract without rewriting them. Historical evidence keeps its original
declaration and does not acquire runtime preflight retroactively.

### Session configuration and identity

After constructing the actual Runner and ScenarioSession and declaring the
instruction slots, but before `session.begin()`, `CompiledF4Runtime` calls
`configure_runtime_paths(graph, contract, ((direction, path),),
source_ownership=compiled_inputs['ownership'])`. The real session bind must
produce the same selected path ID and topology identity as the typed admission
binding. Failure stops before any native command begins.

The compiled decoder manifest carries the same graph, contract, selected
`path_mapping`, and source mapping. The live verifier's existing
`_verify_runtime_path_material` path must validate that decoder declaration,
session manifest declaration, compiled topology, and mapping agree before
`contract_preflight` can be reported. The executor derives runtime-path status
from the successfully configured session; it cannot set that status directly
to bypass session admission.

### Fresh replay

Fresh replay reconstructs the F4 admission from the same frozen typed request,
compiled document, artifacts and ownership data, then configures the new
Runner's ScenarioSession before `begin()`. Comparison includes logical/runtime
path mapping, graph and contract digests, selected source mapping, D2 artifact
identities, runtime topology identity, execution binding, assertion join and
the saved session plan. Changed input or source declarations must refuse before
fresh native commands start. First and fresh execution nonces remain distinct;
identity normalization may only use explicit run-scope bijections already
supported by the replay machinery.

## Failure handling

Admission is fail-closed for a changed or non-canonical compiled document,
graph/contract digest mismatch, absent or duplicate F4 row, wrong selected
runtime path identity, path direction/edge/source mismatch, unsupported source
shape, image resource/component/range mismatch, memory region ID/base/size or
permission mismatch, invalid CPU MMIO source or layout mapping, missing bound
instruction source ID, unbound instruction range, wrong logical/runtime ID
mapping, missing/mismatched decoder declaration, and runtime topology drift.

Configuration and replay-identity mismatches refuse before `begin()` when the
necessary objects are available. A per-case source or range mismatch refuses
before that case's first native command. No mismatch is downgraded to
`legacy_unchecked` after the compiled F4 executor has been selected.

## Acceptance evidence

The software gate must cover:

- accepted same-call F4 graph, contract, selected path and range binding;
- strict rejection for edited graph/contract/path identity, source IDs, edge
  order, image component/resource/width/range, MMIO source/layout and an
  unsupported extra source;
- exact D3 inclusive image range to one real memory region binding, including
  changed memory ID/base/size/permissions and graph width disagreement;
- the logical D3 ID to runtime path ID mapping and case use of the runtime ID;
- explicit bound-instruction source ID round-trip while legacy instruction
  plans retain their current serialized form;
- address before/at start/at last valid word/crossing the exclusive end, wrong
  component, wrong source, wrong path and changed candidate instruction bytes;
- configuration before `begin()` and refusal on post-bind topology drift;
- decoder/session manifest cross-checks, null-contract `contract_preflight`
  refusal, and fresh replay rejection when the admitted source bundle changes;
- preservation of existing generic runtime-path preflight/replay behavior.

The native first/fresh gate must use the existing compiled F4 target and show
that the real ScenarioSession manifest contains the selected runtime contract,
the decoder and session declarations agree, the first/fresh path and source
binding identities match, distinct native executions complete and are reaped,
and full typed-prefix comparison succeeds. Preserve every failed attempt and
its exact inputs. The result remains selected-F4-only and observation/runtime
claims remain limited by the existing assertion and D2 build evidence.

## Explicitly unchanged authority

The result is runtime path contract preflight plus the existing selected-F4
receipt/assertion boundary. It does not prove instruction retirement or
semantic consumption, and it grants no new DMA, ISR, memory-version, or
cross-component acceptance. It does not close P7-E, P6, or P8.
