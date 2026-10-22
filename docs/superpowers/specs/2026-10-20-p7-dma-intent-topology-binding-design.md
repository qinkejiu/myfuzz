# P7-D DMA intent to existing runtime topology binding

Date: 2026-10-20

Status: D4-A artifact links and D4-B Tasks 2–5 are implemented with software
acceptance and independent review. Task 5 carries generated D2/D3 route rows
into an existing typed graph; F6 remains unsupported. No native DMA transaction
or native fresh replay is claimed. This specification does not claim
native/runtime acceptance; its milestones have separate acceptance gates.

## Authority and scope

- [Approved route contract design](2026-10-19-dma-master-route-contract-design.md).
- [Static intent design](2026-10-20-p7-d2-d3-dma-route-intents-design.md).
- [Completed D2/D3 plan](../plans/2026-10-20-p7-d2-d3-dma-route-intents.md).
- Repository `agent.md`: preserve local work; this slice has no remote work.

Bind a canonical `PathWiring` route set to an **existing**
`PreparedRuntimePathContract` route set and the real Runner objects. Require an
explicit bijection; generate a new versioned binding credential. Do not create
or alter a runtime graph, route contract, CPU program, descriptor, provider
operation, feature operation, IRQ path, or executable F6 declaration.

There is enough information in an existing typed runtime graph to validate its
edges. The missing association is `route_id -> (rule_index,
prerequisite_index)`. Historical logical endpoint names introduce a second
association: `runtime endpoint alias -> actual artifact master endpoint`.
Neither association may be inferred from names, direction, address, row order,
the first master, or a method being present.

## Current code facts and limits

| Fact | Source | Consequence |
|---|---|---|
| Live contracts bind typed edges and separate bus initiation from data direction | `scenario/runtime_path_contract.py:517` | Reuse existing selections, including reverse read data direction |
| Live endpoint hashing currently hashes the session, without resolving its `endpoint_id` | `scenario/runtime_path_contract.py:688` | A route hash alone does not prove a physical master-role mapping |
| Historical aliases are `read_master` and `write_master` | `scenario/dma_runtime_paths.py:59` and the PULP, ZipCPU, Caliptra path modules | Preserve old identities; require explicit alias links |
| The actual wbdmac profile declares `dma.memory` | `configs/peripherals/zipcpu_wbdmac/component_profile.json:131` | Never treat an alias as that profile endpoint automatically |
| Renderer knows the resolved master used for `mwb` assignments | `local_harness/runtime_renderer.py:804` | Issue new artifact link evidence at this generation seam |
| Current artifact has adapted IDs, ABI, templates and source hashes | `local_harness/runtime_renderer.py:1243` | These are validation inputs, not an already-issued endpoint-link credential |
| Driver rendering changes the final artifact digest | `local_harness/driver_renderer.py:1133` | Finalize artifact links only after driver generation |
| Peripheral live contract requires component == target ID | `scenario/runtime_path_contract.py:195` | Initial D4 refuses independent device IDs it cannot preserve |
| Window base is 4 KiB aligned; reads have a UART-specific restriction | `local_harness/wishbone_dma_session.py:95,109` | No general subwindow/read-provider expansion |
| RAM binding requires an exact full region and shared memory/service/ledger | `scenario/runtime_path_contract.py:744` | Static contained subranges and permission subsets can remain unsupported |
| P7-C omits F6 runtime edges | `scenario/compiled_paths.py:2847` | Keep that behavior and its refusal reasons |

Paths in the table are relative to `src/myfuzz/`, except the configuration path.
Line numbers describe the reviewed working tree and are navigation aids.

## Milestone D4-A: artifact endpoint-link evidence

D4-A is independently deliverable. It proves how a generated artifact exposes a
declared endpoint through its generated backend. It does **not** prove that a
Runner has that artifact, a live target exists, or a DMA request occurred.

Add an opt-in generation facade:

```python
def render_dma_linked_runtime(plan, structural, source_verification, *,
                              base_dir, provider_id) -> DmaLinkedRuntimeArtifact: ...
```

`DmaLinkedRuntimeArtifact` is frozen and contains the ordinary final
`LocalRuntimeArtifact` as `.artifact` and a canonical link document as
`.endpoint_links_document()`. The ordinary runtime artifact document remains
unchanged. Use a separate closed `dma_linked_runtime_artifact.v1` export wrapper
with exactly `schema_version`, `runtime_artifact`, `endpoint_links`, and
`identity_sha256`; the digest covers all fields except itself.

The generator collects role-link facts where it actually maps the resolved
endpoint to backend assignments. An internal optional collector is empty for
the existing render path. After ordinary driver rendering, a registered issuer
finalizes the facts against the final artifact. Do not issue evidence by merely
finding an endpoint in an old artifact or by copying `adapted_endpoint_ids`.

The closed `dma_artifact_endpoint_links.v1` document has exactly:

| Field | Requirement |
|---|---|
| `schema_version` | `dma_artifact_endpoint_links.v1` |
| `provider_id`, `provider_version`, `provider_contract_sha256` | Exact registered issuer contract; no module/import/callback strings |
| `runtime_artifact_sha256` | Canonical digest of the complete final ordinary runtime document |
| `runtime_sv_sha256`, `cpp_sha256` | Match the final artifact document and generated text |
| `links` | Nonempty array sorted by unique `link_id` |
| `identity_sha256` | Canonical digest excluding this field |

Each link has exactly `link_id`, `endpoint_id`, `function`, `protocol_side`,
`backend_channel`, `template_binding`, and `roles`. `template_binding` has the
six D2 endpoint-binding fields: `profile_endpoint_sha256`, `template_id`,
`template_version`, `variant_id`, `contract_sha256`, `selection_sha256`.
`roles` is the sorted, complete physical role map emitted from the actual
assignment inputs: each row has `role`, `direction`, `width`, `physical_port`,
`member_path`, `raw_lo`, `raw_hi`, `port_width`, and `backend_port`.

The first issuer is the explicitly registered
`wishbone-dma-single-master.v1`, for the generated single-master Wishbone DMA
edge transport only. It uses the resolved `dma_master`, `DMA_MASTER_SHAPE`, the
selected `master.wishbone-pipelined` contract, and the actual `mwb` assignments.
It validates `dma_edge_policy`, `dma_edge_contract`, structural ABI, generated
executor/template selection, and final artifact hashes. `mwb` is a registered
implementation channel, not a name from which a role is inferred. Wrong roles,
missing fields, a second master, a different backend mapping, or a mismatched
template selection refuse issuance.

The issuer records a physical endpoint, not `read_master` or `write_master`.
Logical alias association belongs to D4-B. Additional protocol issuers require
separate implementation and tests; unregistered shapes refuse.

## Milestone D4-B: explicit route and endpoint association

Public APIs:

```python
def prepare_dma_intent_binding(wiring, prepared, *,
                               route_links) -> PreparedDmaIntentBinding: ...
def bind_dma_intent_topology(declaration, runner, *,
                            artifact_links) -> BoundDmaIntentTopology: ...
```

`wiring` is a strict v2 `PathWiring`; `prepared` is an existing
`PreparedRuntimePathContract` with nonempty typed routes. `artifact_links` maps
explicit instance IDs to newly issued D4-A link documents. No factory, native
command, build, source crawl, filesystem scan, or subprocess runs in these APIs.
The ordinary artifact/session construction remains the caller's responsibility.

`PreparedDmaIntentBinding.document()` is a closed
`dma_intent_binding_declaration.v1` object with exactly `schema_version`,
`wiring`, `prepared_runtime_paths`, `route_links`, and `identity_sha256`.
Embedded documents retain their existing schemas and canonical bytes. Parse
them using their existing strict readers. Rows sort by static `route_id`.

Each route-link row has exactly `route_id`, `rule_index`,
`prerequisite_index`, `runtime_route_sha256`, and `endpoint_link`. The closed
`endpoint_link` has exactly:

```text
mode: exact_id | explicit_alias
static_endpoint_id
runtime_endpoint_id
artifact_endpoint_id
artifact_link_id
artifact_link_provider_id
operation: read | write
template_binding: the six D2 initiator-binding fields
```

Every field is explicit. Match `static_endpoint_id` to the intent;
`runtime_endpoint_id` and operation to the selected typed route; and the actual
endpoint ID, provider, role, template and fingerprints to the D4-A artifact
link. `template_binding` must equal D2's retained initiator binding and the
artifact credential's complete binding. Its fingerprint is recomputed from the
actual artifact plan/profile and endpoint. Verify all six fields, including the
selection digest, not just the template label.

For `exact_id`, all three endpoint IDs must be equal. This common path has no
scenario-name or protocol-name dispatch. It still requires artifact role-link
evidence and an admitted live session provider; exact text equality alone is not
physical evidence.

For `explicit_alias`, the static and artifact endpoint IDs must be equal; the
runtime logical alias may differ. A registered live provider must certify that
this session drives the credential's backend channel for the explicitly stated
operation. The first provider admits the generated single-master Wishbone DMA
session family and its pinned edge contract only. The caller supplies the
logical alias; the verifier compares it literally with the typed route and does
not inspect its spelling. Two differently named read/write aliases may link to
the same actual master when their explicit operation and typed edges match.
No default mapping for `read_master` or `write_master` exists.

The complete route sets must be bijective: one intent per typed route, one link
per intent, no duplicate edge keys, no unselected route, and no unused link.
Identical policies on different graph edges do not justify automatic matching.

### Static to live field mapping

| Static field | Live source/check |
|---|---|
| `route_id` | Explicit edge mapping; do not add it to historical runtime v2 rows |
| `initiator_instance` | `route.initiator_component` and that exact Runner session |
| `initiator_endpoint_id` | Endpoint-link checks above |
| target `kind`, `component_instance` | `target_kind`, `target_component` and exact target session |
| target `resource_id` | Exact memory `target_id`, full region/alias policy supported by existing binder |
| target `device_id`, `endpoint_id` | Exact static wiring window and target artifact endpoint; initial D4 additionally requires device ID == component == live target ID |
| aperture, operation, permissions, byte enable, offsets | Exact values in the existing runtime route and actual window/region |
| accepted values | Type plus ordered tuple values or exact range start/stop/step |
| D2 target binding | Recompute target endpoint/profile/template or owner/resource fingerprints from actual artifacts and wiring |
| No static field | Preserve both existing live identity hashes, source/target node IDs, graph and route hashes |

Never copy a static hash into `endpoint_identity_sha256` or
`target_identity_sha256`. Use the existing runtime identity helper documents
and compiler to revalidate both real identities. Memory execute/initialization
declarations remain static profile facts; this binding grants no new memory
execution or initialization authority.

### Live bind, credential and mutation checks

Preflight all artifact links and route associations before binding. Then call
the existing `prepared.bind(runner)` exactly once with an additional optional
`topology_guard` callback. Thread that callback through the existing compiler
into `CompiledRuntimePathContract.validate_topology()`; default is `None` and
serialized documents remain unchanged. The existing session callback therefore
rechecks both ordinary topology and endpoint-link evidence before startup,
case admission and target side effects. The guard snapshots real session,
artifact/plan objects, link-document bytes and relevant metadata; it does not
call the compiled validator recursively. Session/artifact/link replacement,
including an equal replacement object, refuses.

Every participating Runner session-map key must equal the actual generated
artifact's `plan.request.instance_id`, for both DMA initiators and target
components. Check this before binding and repeat it in the pinned topology guard;
a caller-selected map key does not rename the artifact.

`BoundDmaIntentTopology` is frozen, exposes `.runtime_compilation`,
`.document()`, `.identity_sha256`, and `.validate_topology()`. The latter invokes
the existing compiled validator including the guard.

Its closed `dma_intent_topology_binding.v1` credential has exactly
`schema_version`, `declaration_sha256`, `prepared_sha256`,
`runtime_contract_sha256`, `runtime_compilation_sha256`, `topology_sha256`,
`artifact_links`, `routes`, `tier`, and `identity_sha256`. `tier` is exactly
`topology_bound`. `artifact_links` contains sorted `{instance_id,
endpoint_links}` rows. `routes` contains sorted `{route_id, intent_sha256,
rule_index, prerequisite_index, runtime_route_sha256, endpoint_link_sha256}`
rows. All hashes are recomputed. The credential neither signs its own truth nor
substitutes for source/build admission: the registered issuer, pinned payload,
external saved identity and fresh-object validation remain required and are
enforced by the bound replay path.

## Saving and replay versions

Do not extend old closed runtime-path records or old numbered online plans in
place. Leave existing v1/v2 graph, contract, prepared, compilation, edge-index,
decoder, artifact and historical evidence bytes unchanged.

Use a closed outer `p7_dma_bound_payload.v1` document with exactly:

```text
schema_version
payload_kind: online_session_plan | fresh_run_identity
payload_encoding: base64
payload_bytes
payload_sha256
binding_declaration
binding_compilations
identity_sha256
```

`payload_bytes` encodes the **original complete ordinary document bytes**,
including the ordinary online plan or fresh identity envelope. Base64 must be
canonical; nesting another bound envelope is refused. `payload_sha256` hashes
the decoded bytes. `binding_compilations` is a nonempty sorted array of
`{selection_id, credential}`: exactly `session` for online session payloads, or
exactly the ordinary prepared path IDs for fresh execution payloads. All
selected routes must still be covered by the existing prepared selection rules.

The outer digest covers every field except itself. Bound replay entry points
also require the expected outer identity digest from the verified report/run
manifest. New bound reports mark the binding schema as required and record both
outer binding digest and inner payload digest. Do not rely on a removable
optional sidecar. Historical trace genome/plan hashes retain their inner-byte
meaning; keep the distinct outer binding digest as a separate required identity.

The existing old readers reject the new outer schema: online plans require an
integer schema and closed keys; fresh replay requires
`scenario_fresh_run_identity_envelope.v1`. Do not add a fallback that unwraps an
unknown schema or treats missing binding material as a legacy run.

New readers perform two phases:

1. **Before any Runner factory or native operation:** validate closed outer
   schema, expected digest, payload bytes/digest, existing inner readers,
   binding declaration/credential hashes, complete route/edge/link sets,
   artifact-link shapes and registered issuer contracts, and agreement with
   saved runtime compilations using `RuntimeEdgeIndex`. Any corrupt or omitted
   material fails here. A wholly forged coherent bundle is not authenticated by
   recomputing its own hashes; the caller's pinned expected identity is required.
2. **After a fresh Runner exists, before process startup:** revalidate actual
   session artifacts, role links and target objects; bind once; recompute and
   compare the full credential. Keep original prefix/transaction replay checks.
   The wrapper itself never grants `replay_verified`.

Integrate with `session_runtime.configure_runtime_paths`, its plan serialization
and `replay_online_session`; `ScenarioRfuzzExecutor._runtime_preflight` and
`_install_runtime_replay_identity`; and the fresh/online identity writers and
verifiers in `scenario_rfuzz_live.py`. Add explicit bound-envelope dispatch while
retaining the legacy branches and inner byte/hash semantics.

## Refusals and current adapter inventory

Use a `ValueError` subclass carrying stable `code` and JSON `pointer`. Required
codes cover `dma-binding-route-set-mismatch`, `dma-binding-edge-mismatch`,
`dma-binding-policy-mismatch`, `dma-binding-endpoint-link-required`,
`dma-binding-endpoint-link-mismatch`, `dma-binding-provider-unsupported`,
`dma-binding-artifact-mismatch`, `dma-binding-template-mismatch`,
`dma-binding-target-unsupported`, `dma-binding-topology-changed`, and
`dma-binding-replay-material-invalid`. Contradictory supplied declarations
refuse; absence never causes graph generation or causal-order fallback.

| Existing input | Initial disposition |
|---|---|
| Existing wbdmac runtime artifacts | Missing new generation-issued link evidence; refuse until a separate new D4-A artifact is issued |
| UART, PULP GPIO, ZipCPU UART, Caliptra path builders using logical aliases | No implicit migration; supply explicit link rows and admitted artifacts or refuse |
| Generated single-master Wishbone DMA with new D4-A evidence | First admitted master-link provider; aliases still need explicit D4-B association |
| Exact-ID route with admitted artifact link and live provider | Generic positive path |
| Different backend, multiple master channels, missing complete role facts | Refuse; no first-master selection |
| Generic target whose profile/template cannot be tied to actual adapted endpoint | Refuse; method names do not establish target identity |
| Independent device ID, unrepresentable subwindow, broader/narrower live policy | Named refusal in this initial schema |
| Unknown provider or fake artifact/session with matching JSON only | Refuse live admission |

No current historical adapter is claimed to already supply the new credential.
D4-A acceptance must precede D4-B provider acceptance. Regenerate new artifacts
in a new output directory; never update frozen historical evidence in place.

## Acceptance and capability boundary

Use the compact matrix in the implementation plan. Software fixtures may prove
parsing, linkage and live object checks without issuing commands. Label them
software topology tests. A real native run is not required to close these
milestones and is not claimed by them.

D4-A grants `artifact_endpoint_linked` for its exact generated artifact only.
D4-B grants `topology_bound` for the exact supplied intent and existing typed
runtime route set only. Neither grants executable P7-C F6, CPU configuration,
DMA request/response evidence, transfer data pairing, target effects, RAM commit
authority, completion IRQ/ISR, continuous fuzzing, performance gates, or fresh
native prefix reproduction. Keep F6 `unsupported` with
`dma-route-live-topology-binding-required` for static route-bearing P7-C output,
and `dma-master-route-undeclared` when no route exists. P7/P8 remain open.
