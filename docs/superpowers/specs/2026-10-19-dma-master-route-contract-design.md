# Versioned DMA Master Route Contract

**Status:** Approved for implementation on 2026-10-19. This document specifies the accepted design; it does not claim implementation or runtime results.

## Context

The project already has a real ZipCPU `wbdmac` → OpenTitan UART data path. P8 S2–S4 cover multiword transfers, error ISR handling, source admission, and typed-prefix replay for the declared UART cases. The source graph in `src/myfuzz/scenario/dma_runtime_paths.py` still labels the DMA-master edge `causal_order`; `declared_dma_master_route()` separately checks one UART `MasterTargetWindow` and UART-specific `master_target_access()` behavior. The shared `RuntimePathContract` supports direct bindings, CPU MMIO routes, causal order, and persistent state, but has no typed DMA-master route. P7 F6 therefore reports `dma-master-route-undeclared` even when component declarations describe a real transfer provider.

This prevents safe reuse of the existing route evidence for the other selected IP series. The four series are OpenTitan TL-UL, PULP APB3, ZipCPU Wishbone/AXI4-Lite, and Caliptra AHB-Lite. Only the OpenTitan UART target currently has real DMA FIFO evidence.

## Goals

1. Give a declared DMA path a versioned, typed relation that identifies the actual DMA master endpoint and the exact destination route it can use.
2. Bind the declaration to the live Runner topology: the same DMA session, exact `MasterTargetWindow` or persistent-memory resource, aperture, permissions, endpoint identity, and route configuration used by execution.
3. Carry the same per-beat DMA transaction identity from the accepted master request through the target operation and native response. A read→write transfer keeps distinct read and write keys, paired by measured order and exact data value. RAM effects join to the real memory version event; peripheral effects join to the real target transaction and measured device effect.
4. Preserve fail-closed behavior. Missing, ambiguous, changed, or internally inconsistent route declarations are refused before the first RTL command. A runtime request outside the declared aperture or permissions is refused before its target side effect; an explicitly declared negative case may still issue that real request and receive the real DMA error response. A denied/error transaction does not count as a successful transfer.
5. Migrate the existing OpenTitan UART RX FIFO → DMA → RAM S4 path first, preserving prior evidence as historical evidence with its original identities.

## Approach choice

The selected approach is one versioned shared route contract, first consumed by the existing UART S4 path. Extending only the UART-specific graph would be faster but would leave the same assumptions trapped in one scenario. Building separate adapters for every IP now would duplicate route identity and transaction-join rules before the common contract is stable. The shared contract costs an explicit schema migration and topology validator, while allowing later protocol providers to supply their own endpoint semantics without weakening the common identity checks.

## Non-goals

- This slice does not add a DMA provider or claim a DMA path for PULP, ZipCPU UART, or Caliptra. Those are later provider-specific integrations.
- It does not synthesize bridges, arbiters, interconnects, a SoC bus, or global cycle-accurate timing.
- A route declaration or topology compile is not proof that a transfer occurred. Runtime proof still requires joined native request/response and target-effect evidence.
- It does not prove CPU decode, retirement, ISR semantics, arbitrary same-protocol RTL support, or P6/P7/P8 completion.
- It does not promote the existing bounded S4 case into continuous DMA fuzzing or the P8 5× performance result.

## Contract shape and compatibility

Keep serialized `runtime_path_contract.v1` documents byte-for-byte stable when they contain no DMA route. Add a closed `runtime_path_contract.v2` form for contracts that declare one or more DMA routes. The v2 document contains the existing graph and edge declarations plus a sorted `dma_master_routes` array. Add dependency kind `DMA_MASTER_TRANSFER` and relation `dma_master_route`; only that kind/relation pair is valid. Each route binds to an explicit selected graph edge joining the DMA master access node and the real target-operation node; it is not a sidecar disconnected from the path graph. Edge direction follows data flow: for a read, the target read result precedes the DMA receive node; for a write, the DMA accepted payload precedes the target effect node. The route separately records which component initiates the bus request. The current decoder continues to accept v1; a v1-only reader must reject v2 rather than silently dropping routes, and a decoder that accepts v2 must reject unknown fields or relation values.

Each route is tied to one dependency edge and declares:

- the DMA component, endpoint ID, and pinned endpoint/profile identity;
- a tagged target: either a persistent-memory component/resource or a peripheral component/device endpoint;
- the exact address aperture and permitted read/write operations;
- target-specific offset/byte-enable constraints where the target requires them;
- the complete target-window identity, including an injective serialization of accepted write values: tuples as ordered value lists and ranges with their exact `start`, `stop`, and `step`;
- the dependency edge key and source/target node IDs;
- the route identity derived from the canonical declaration.

For a peripheral target, compilation must find exactly one matching live `MasterTargetWindow`, prove its endpoint object is the declared live session, and compare its complete identity document and permissions with the declaration. The route identity must not rely on the current range summary `[start, stop-1]`, which omits `step`; v2 must encode the accepted-value policy without collisions. The common route record abstracts addressing and identity only; each peripheral still needs a provider-specific target adapter for its actual transaction and observation semantics. For RAM, compilation must prove the DMA session's `memory_service.memory` is the same `PersistentMemory` object declared by the CPU/RAM topology, and that the declared resource, aperture, and permissions match its regions. The S4 runtime join uses its actual `memory_write` event and memory version; it must not claim an issued service commit receipt unless the commit stream is explicitly enabled and that receipt is independently joined. A route may not be inferred from a protocol name, profile label, address alone, or an endpoint method name.

The contract compiler snapshots the selected DMA session, target session, `MemoryService`, `PersistentMemory`, ledger, memory/window objects, endpoint identities, and immutable route list. `validate_topology()` rechecks those exact objects and identities before every case admission and before every DMA master beat can cause a target effect; a post-compile mutation cannot wait until the next fresh run to be noticed. Adding a route changes the v2 contract and provenance digests; it does not rewrite old saved evidence or historical v1 identities. New prepared-path, topology-compilation, runtime-edge-index, and DMA-source-provenance documents use v2 schemas when they carry these routes; their readers continue to accept v1 and preserve its canonical bytes. Update the saved-plan/replay readers in `session_runtime.py`, `scenario_rfuzz_live.py`, and `scenario_rfuzz.py` so a v2 route cannot be dropped during fresh replay. The runtime edge index must expose route-edge identities to source/transfer evidence joins without converting `dma_master_route` into a generic causal-order match.

## Runtime data flow

For each individual DMA master beat, the runtime join uses one exact transaction key and verifies:

1. the pinned DMA native edge accepted the request with the declared address, direction, data, and byte-enable shape;
2. the real target endpoint or memory service received that same key and performed the declared operation;
3. a successful RAM write joins to its actual committed memory version, or a peripheral write/read joins to its actual target receipt and measured device effect;
4. the same key received exactly one native response, or an explicit error response;
5. the target, address range, permission, and endpoint identity match the compiled route.

The target operation may occur when an accepted request is serviced, before the native response is observed; the join records measured local phases and does not impose a cross-component cycle order. A transfer's read and write are different master transactions: they share execution, case, source, epoch, and channel identity, use distinct adjacent sequence numbers in read-then-write order, and carry the same measured value from the source response/FIFO pop into the accepted destination write and committed value. The same key is required only within each individual request→target operation→response join. Duplicate, missing, reordered, or mismatched transaction evidence is refused or retained as incomplete diagnostics; it cannot produce a successful transfer relation. Static route validation remains separate from these runtime facts.

## First migration and later expansion

The first consumer is the existing OpenTitan UART RX FIFO → DMA master RDATA read → RAM commit S4 path. Migration adds explicit graph nodes and DMA→UART and DMA→RAM route edges; the existing `cpu.fifo_pop → dma.fifo_pop` causal edge remains a distinct ordering relation. The UART-specific route check becomes an adapter that emits the common route declaration and per-beat runtime joins. UART source admission and FIFO-pop proof remain required. The existing S4 checker must still pair the distinct read/write keys, prove the admitted UART byte equals the real read result, and prove that value equals the DMA RAM write/version event; the route contract does not replace this transfer-level proof.

After the common route and UART migration are independently accepted, add separate provider-adapter slices for PULP APB3, ZipCPU AXI4-Lite/Wishbone UART, and Caliptra AHB-Lite SHA256. Each provider must declare its own real DMA endpoint, target route, permissions, and measured operation semantics; the common route record alone does not make the current UART-only `MasterTargetWindow` implementation support those targets. Unsupported shapes remain named unsupported paths.

P7 `PathWiring` and D3 F6 compilation are outside this first migration. Merely adding runtime contract v2 must not make F6 executable: until the separate D3 wiring/compiler integration lands, F6 remains `unsupported` with `dma-master-route-undeclared`. This first slice retains a negative check for that refusal.

## Error handling and capability reporting

Planning or preflight returns a stable refusal code and pointer when the master endpoint, target resource/window, identity, permissions, or transaction linkage is absent or contradictory. Do not downgrade a malformed route to `causal_order`. Capability reports distinguish:

- `declared`: a closed route declaration exists;
- `topology_bound`: it resolves uniquely against the real Runner objects;
- `runtime_observed`: the actual transaction and target effect joined;
- `replay_verified`: an independent fresh process reproduced the typed prefix.

No higher tier is implied by a lower one.

## Acceptance evidence

The implementation plan should require:

- strict v1/v2 serialization tests, including v1 byte identity and unknown-field rejection;
- negative topology cases for missing/ambiguous windows, wrong endpoint identity, wrong memory resource, permission mismatch, aperture overflow, and post-compile topology mutation;
- transaction-join cases for missing/duplicate responses, per-beat key mismatch, read/write pair mismatch or reorder, target error, missing RAM version event, and successful RAM/peripheral effects;
- topology checks that reject unsupported claims of issued commit authority and detect complete target-window identity changes, including collision cases for range step and tuple/range encoding;
- migration of the UART S4 route with unchanged source-admission requirements and a new frozen identity;
- an integration boundary check proving P7 F6 remains unsupported until its D3 wiring/compiler change;
- a real native positive run plus controlled route/target failure and independent fresh-prefix replay before claiming the migrated runtime path.

The reader inventory for the implementation plan includes `RuntimePathContract.from_document()`, `PreparedRuntimePathContract.from_document()`, `RuntimeEdgeIndex`, and saved-plan/replay entry points in `session_runtime.py`, `scenario_rfuzz_live.py`, and `scenario_rfuzz.py`.

This slice is complete only for the shared route contract and migrated UART S4 scope. It does not close the four-series DMA objective or any full P6/P7/P8 gate.
