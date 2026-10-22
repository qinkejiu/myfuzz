# P7 post-live F6 runtime path compiler

Date: 2026-10-21

Status: bounded design. The static `compiled_paths.v1` F6 refusal remains the
compiler contract; this design adds a separately versioned runtime artifact
after live endpoints are available.

## Goal and boundary

The current Caliptra SHA256 DMA native gate proves a real RAM read, an AHB-Lite
`CTRL=5` write, D4 route admission, pre-provider refusal, and fresh replay. Its
runtime graph is still built by `prepare_caliptra_sha256_dma_runtime_paths()`.
This slice replaces that graph construction with a shared compiler over the
existing route intent and runtime contract types.

The first accepted shape is exactly one aligned four-byte read from a declared
`PersistentMemory` resource and one full-word write to the declared Caliptra
SHA256 `CTRL` aperture at offset `0x10`, with the accepted value `5`. The two
route IDs are explicit inputs and their order has no meaning. The generated
path includes two `DMA_MASTER_TRANSFER` edges and one `EVENT_ORDER` edge that
requires the read response before the write. The native policy still proves
that the read value is the value written.

This artifact proves a transfer-only runtime path prepared from a static
declaration plus a live topology. It does not make static F6 executable, prove
CPU DMA programming or retirement, prove IRQ/ISR behavior, or close P7-E.

## Static and live artifacts

The existing P7-C compiler remains unchanged:

- `compiled_paths.v1` F6 stays `unsupported` with
  `dma-route-live-topology-binding-required` and `runtime_path_identity=null`.
- The compiler emits no `DMA_MASTER_TRANSFER` rule or edge.
- `CompiledF6DmaHandoff` continues to reject a static compiler result that
  contains a DMA runtime edge or route.

A new closed `compiled_f6_runtime_path.v1` is produced later, when a real
Runner, DMA session, memory service, target provider and artifact endpoint
links are present. It records the exact static compiler and wiring identities,
the source-word descriptor, the explicitly paired route IDs, the generated
dependency graph, the existing `RuntimePathContract`, and the complete
route-ID-to-edge bijection. Its canonical digest covers the entire document.

The exact closed wire shape is:

```json
{
  "schema_version": "compiled_f6_runtime_path.v1",
  "source": {
    "schema_version": "dma_transfer_source_word.v1",
    "memory_component": "cpu",
    "resource_id": "ram",
    "image_id": "sha_ctrl_start",
    "address": 65792,
    "word_bytes": 4,
    "byte_enable": 15,
    "direction": "CPU_TO_IP"
  },
  "transfer_pair": {
    "schema_version": "dma_transfer_route_pair.v1",
    "read_route_id": "route.ram-read",
    "write_route_id": "route.caliptra-ctrl",
    "relation": "same_word_value"
  },
  "compiled_f6_handoff": {"schema_version": "compiled_f6_dma_handoff.v1"},
  "identity_sha256": "<sha256>"
}
```

The `compiled_f6_handoff` value is the full existing handoff document, not a
placeholder or digest-only reference. It carries the full D3 result and its
`compiled_document_sha256`, D2/D3 wiring and route/binding identities, the D4
declaration and route links, and `prepared_runtime_paths` (graph, contract,
and selected path). The outer identity is SHA256 over sorted-key compact
UTF-8 JSON with non-finite numbers rejected, after removing only the outer
`identity_sha256` field. The nested D3 digest must use the existing
`compiled_document_sha256()` function; it has a distinct historical canonical
JSON rule.

The closed source fields are exactly `schema_version`, `memory_component`,
`resource_id`, `image_id`, `address`, `word_bytes`, `byte_enable`, and
`direction`. The descriptor reader validates types, a nonnegative aligned
unsigned-64-bit address, `word_bytes=4`, `byte_enable=15`, and
`direction="CPU_TO_IP"`. Region membership is checked during live preparation
against both the declared read intent and the exact canonical
`PersistentMemory` region; a detached descriptor has no region facts and must
not claim that check.

The closed pair fields are exactly `schema_version`, `read_route_id`,
`write_route_id`, and `relation`. The two route IDs are nonempty, distinct,
and relation is exactly `same_word_value`. They must equal the entire route
set in the static D2/D3 declaration, with one `read` persistent-memory route
and one `write` peripheral route using the same initiator and full-word
policy. The read route's resource and address range must match `source`; the
write route must name the Caliptra SHA256 `sha256.bus` CTRL word at offset
`0x10`, and accept only value `5`.

`CompiledF6RuntimePath.from_document()` validates the artifact's internal
identity and embedded D3/D4 chain. `prepare_compiled_f6_runtime_path()` also
compares that chain to the actual `compiled_paths` and `wiring` inputs for the
current live run. A self-consistent detached digest is an identity check, not
an authenticity claim about who produced the document.

The live preparation result carries process-local provenance tied to the exact
`PreparedRuntimePathContract` retained by its D4 handoff. A value returned by
`from_document()` is detached and cannot be passed to the live bind API, even
when its digest and all embedded declarations are valid. Direct dataclass
construction also cannot mint that provenance. The compiler compares the
complete supplied D3 route and binding identities to the normalized
`PathWiring` before creating the runtime graph.

The runtime graph is also closed to the one supported shape: source node
`ram.source_word`; DMA nodes `dma.read_data` and `dma.write_data`; target node
`sha.ctrl_start_effect`; a RAM-read `DMA_MASTER_TRANSFER` rule, then an
`EVENT_ORDER` rule from read response to write, then the CTRL-write
`DMA_MASTER_TRANSFER` rule. Its `RuntimePathContract` has exactly the
corresponding two `dma_master_route` edges and one `causal_order` edge. The
prepared selection must preserve the descriptor's direction and source
identity. Route input order is immaterial at compilation: explicit route IDs
select the two edges, and reversed input intent tuples yield the same
canonical artifact. Serialized D4 route-link arrays remain canonical and
are rejected if reordered or duplicated.

The public preparation API is:

```python
prepare_compiled_f6_runtime_path(
    compiled_paths,
    wiring,
    runner,
    *,
    source,
    transfer_pair,
    artifact_links,
) -> CompiledF6RuntimePath
```

`source` is a closed `dma_transfer_source_word.v1` value with the exact fields
and checks above. It identifies the allowed source location; it does not
assert that a read happened or supply runtime payload bytes.

`transfer_pair` is a closed `dma_transfer_route_pair.v1` value containing the
read route ID, write route ID, and `relation="same_word_value"`. The helper
resolves both IDs against the declared route set and refuses missing,
duplicate, extra, ambiguous, cross-master, wrong-operation, wrong-target, or
policy-incompatible rows. It never infers the pair from tuple order, names, or
addresses.

Preparation constructs the dependency graph and existing typed runtime
contract, then creates the existing `PreparedDmaIntentBinding` and exact static
F6 handoff. The result retains the same prepared contract object used by D4.
`bind_compiled_f6_runtime_path(path, runner, artifact_links=...)` delegates to
`bind_compiled_f6_dma_handoff()` exactly once; no second graph is constructed.
Route beat admission remains responsible for checking each real read/write
transaction, and the Caliptra provider continues to enforce its current
full-word `CTRL=5` policy.

The live Caliptra route validator and the single graph/contract builder live
below the Caliptra compatibility wrapper: `caliptra_sha256_dma_paths.py`
delegates to them, and the compiler does not import that wrapper. This keeps
the shared graph construction single-sourced without a module cycle while
preserving the existing memory-owner, canonical-region, DMA-window, SHA
provider, protocol-trace, artifact-link, and CTRL policy checks.

## Validation and refusal

Before a prepared artifact is returned, validation must establish:

1. The supplied compiler document is a valid static F6 refusal and its
   embedded route digest is identical to the supplied D2/D3 wiring contract.
2. The two explicit route IDs form the whole F6 route set for this one-word
   slice. The read route targets the exact declared persistent-memory
   resource; the write route targets the exact declared peripheral endpoint.
3. Both routes use the same declared DMA initiator and full-word policy.
4. The source address is inside the exact canonical live memory region named
   by both the route and the descriptor; the image ID and graph source match.
   Live memory, memory service, DMA session, target window, target provider,
   and generated artifact links satisfy the existing topology binder's exact
   owner and identity checks.
5. The prepared graph round-trips through `DependencyGraph` and
   `PreparedRuntimePathContract`; it has the fixed three-rule/two-transfer
   shape above. Every DMA edge has exactly one runtime route contract and
   every route contract names exactly one edge. The `RuntimePathContract`
   reader validates the typed nodes, edge relations, and route policies.
6. The final bound wrapper references the exact prepared graph and its
   `CompiledF6DmaHandoff`; it binds the Runner once.

Contradictory source addresses, partial words, unrelated RAM regions, wrong
route operations, extra routes, duplicate or swapped links, stale endpoint
identities, and Caliptra window/provider drift fail before native side effects.
The existing `CTRL+4` negative case continues to refuse before provider
dispatch and creates no effect for the rejected transaction key.

## Fresh replay and evidence

The fresh run independently recompiles D3, rebuilds `compiled_f6_runtime_path.v1`
from its own Runner and artifact links, creates a new topology binding, and
executes the same positive and refusal cases. Runtime graph, route mapping,
source descriptor and normalized semantic identities must match; execution,
Runner, session and provider owner identities must be fresh. Evidence stores
the static compiler result, runtime-path artifact, bound wrapper, read/write
route matches, typed transaction identities, provider effects, refusal order,
and normalized fresh comparison.

Identity-bound D3, runtime-path and handoff documents are compared before
normalization. Fresh semantic equality is computed from a separate transaction
event projection that normalizes only the execution fields defined by that
event schema; recursive string/key replacement must not rewrite artifact
identities or conceal owner changes. Runner, session, memory, prepared-path,
handoff and native-process distinctness are asserted separately from semantic
equality.

The design does not add a physical Wishbone-to-AHB bridge, DMA interrupt
delivery, CPU configuration/consumption, multiword transfers, arbitrary
targets, or a general statement that F6 is executable.
