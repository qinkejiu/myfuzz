# P7-B/P7-C static DMA route intents

Date: 2026-10-20

## Goal

Carry explicit DMA master route intent from a versioned P7-B composition into
P7-C without inferring an endpoint or target from a CPU/IP name, protocol label,
address, or profile directory. Keep static declaration checks separate from the
existing live `DmaMasterRouteContract`, whose endpoint and target identities are
computed from actual Runner objects.

## Static intent schema

`harness_compose.v2` and `wiring_contract.v2` carry a closed
`dma_master_routes` object with this shape; rows are sorted by `route_id`:

```json
{
  "schema_version": "dma_master_route_intent.v1",
  "routes": [
    {
      "route_id": "copy.destination",
      "initiator_instance": "mover",
      "initiator_endpoint_id": "declared.profile.master",
      "target": {
        "kind": "peripheral",
        "component_instance": "output",
        "device_id": "output.window",
        "endpoint_id": "declared.profile.slave"
      },
      "base": 1073745920,
      "size": 4096,
      "operation": "write",
      "permissions": ["write"],
      "byte_enable": 15,
      "readable_offsets": [],
      "writable_offsets": [12],
      "accepted_write_values": {"kind": "range", "start": 0,
                                 "stop": 256, "step": 1}
    }
  ]
}
```

The target is exactly one of `persistent_memory` (`component_instance`,
`resource_id`) or `peripheral` (`component_instance`, `device_id`,
`endpoint_id`). Memory targets must leave the peripheral offset/value fields
empty. Peripheral `readable_offsets` and `writable_offsets` are relative to the
route aperture. `accepted_write_values` is either `{"kind":"values",
"values":[...]}` with order preserved, or `{"kind":"range","start":...,
"stop":...,"step":...}`. The initial schema admits full word byte enable 15,
aligned nonempty apertures, and 32-bit accepted values, matching the existing
live contract's current shape.

Expose `parse_dma_master_route_intents(document, pointer=...)`, returning an
immutable tuple of `DmaMasterRouteIntent`, and
`dma_master_route_intents_document(routes)`, returning the canonical closed
wrapper above. Each intent has `document()` and `identity_sha256`.

Static intent does not contain `endpoint_identity_sha256`,
`target_identity_sha256`, runtime graph rule indexes, session IDs, or claims of
topology binding. Those fields belong to the already implemented live route
contract and must be derived from real runtime objects.

## Static profile and template bindings

The route intent rows remain protocol-neutral and contain no fingerprints. A
`harness_compose.v2` document carries one closed `dma_master_route_bindings`
row per route. Each row has `route_id`, an `initiator_template` selection with
`template_id`, `template_version`, and `variant_id`, and a `target_template`
selection with the same fields for a peripheral target. A persistent-memory
target has no target template selection. Selection is explicit even when a
registered shape-only contract could otherwise be selected automatically.
The selector is checked against the exact profile endpoint and its resolved
shape; it never selects by a component or instance name.

For component control endpoints already required by P7-B, `harness_compose.v2`
may also declare a `template` selector on the CPU/device row. This is separate
from a route endpoint selector because one component may expose both a control
slave and a DMA master. V1 composition keeps its existing shape-only behavior
and bytes.

The generated `wiring_contract.v2` carries one `dma_master_route_bindings` row
per canonical intent. For component endpoints, each binding records
`profile_endpoint_sha256`, selected template ID/version/variant, the registered
template contract digest, and the selected-template digest. For persistent
memory, the target binding records the owner profile fingerprint and exact
normalized resource digest instead of an endpoint/template. The endpoint
fingerprint is SHA-256 of canonical JSON for
`{"profile_fingerprint": <profile.profile_fingerprint>, "endpoint_id": <id>}`;
the resource fingerprint is SHA-256 of the exact normalized wiring resource
row. These are static declaration fingerprints, not live Runner identities.
P7-C recomputes the profile-endpoint and resource fingerprints from its loaded
profiles/wiring and preserves the binding rows with the intent in the compiled
wiring identity.

## Versioning and compatibility

- Existing `harness_compose.v1` and its generated `wiring_contract.v1` remain
  byte-for-byte unchanged when no DMA routes are declared.
- A composition carrying routes uses `harness_compose.v2`, and generated
  `wiring_contract.v2` retains the normalized route rows. Its containing
  harness-set document uses a matching version so a v1 reader cannot silently
  treat routes as understood.
- P7-C accepts both wiring versions with strict, version-specific closed keys.
  A v1 document containing route fields, an unknown v2 field, or an invalid
  route reference is refused; no route list may be silently dropped.
- V2 requires one static binding row per route; route and binding IDs must be
  one-to-one, and profile-endpoint/resource fingerprints are recomputed.
- Route order is canonical by `route_id`. No empty v2 route list is accepted.

## Static validation

P7-B resolves each initiator instance and endpoint from the declared component
profile and requires a master endpoint. Peripheral targets must identify one
declared component and exact endpoint; memory targets must identify one declared
resource and its owner. The aperture, permissions, offsets, byte enable, and
accepted-value policy must be internally valid. Selection of a protocol
template, when the endpoint requires an explicit template, is supplied by the
versioned composition and checked against the endpoint's declared shape and
capabilities. No name-based dispatch is added.

P7-C strictly parses and preserves these routes in its wiring identity. It
checks that a `transfer` feature operation names the exact declared master
endpoint before reporting the static intent as compatible. If route declarations
are valid, F6 still remains unsupported for runtime execution with
`dma-route-live-topology-binding-required`; static intent is not a
`runtime_path_contract.v2` route and does not create `DMA_MASTER_TRANSFER`
runtime edges.

## Scope limits

This slice does not create bridges, providers, memory services, or a live
`MasterTargetWindow`; it does not claim an observed transfer, CPU configuration,
completion IRQ/ISR, or executable F6 runtime path. It does not change the
existing runtime route contract v2 or its replay identities. A later D3/D4 slice
must build the existing `DmaMasterRouteContract` from actual Runner objects,
check the CPU configuration and completion path, and join real transaction
evidence before claiming runtime DMA.

## Acceptance evidence

1. Tests prove strict route row parsing, deterministic digesting, exact
   tuple/range identity, and refusal of unknown fields, bad apertures,
   permissions, offsets, duplicate IDs, and fake runtime identities.
2. Legacy v1 composition/wiring/harness-set bytes remain unchanged; v1 route
   fields refuse. Valid v2 routes survive D2 generation and D3 supplement
   merging with exact canonical bytes.
3. D2/D3 tests cover missing/ambiguous initiator, wrong endpoint function,
   unknown target/resource, permission mismatch, and renamed-instance positive
   behavior.
4. A valid static F6 intent stays explicitly runtime-unsupported until live
   topology identity binding; missing intent keeps the existing
   `dma-master-route-undeclared` reason.
5. Reports preserve the open runtime/DMA completion boundaries and do not mark
   P7 complete.
