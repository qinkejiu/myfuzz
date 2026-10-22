# P7-D DMA Intent Topology Binding Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking. D4-A Task 1 and D4-B Tasks 2–5 have software implementation and review coverage as of 2026-10-20. Preserve the shared dirty worktree. Do not stage, commit, reset, clean, or run remote work.

**Goal:** Validate an explicit bijection from P7 static DMA intents to existing
typed runtime routes and issue saved, replayable topology-binding credentials
without creating a runtime graph or enabling F6.

**Architecture:** First issue detached endpoint-role credentials from the actual
artifact generation mapping (D4-A). Then join explicit route/endpoint links to
an existing prepared contract, bind its actual Runner once, and preserve the
result in a required versioned replay envelope (D4-B). Historical inner v1/v2
documents and evidence retain their bytes and identities.

**Tech Stack:** Python 3, frozen dataclasses, canonical JSON/SHA-256,
MappingProxyType, existing local renderer/template admission and runtime route
compiler; pytest software fixtures with native commands guarded by sentinels.

## Global constraints

- Authority: [D4 draft spec](../specs/2026-10-20-p7-dma-intent-topology-binding-design.md), [approved 10-19 route spec](../specs/2026-10-19-dma-master-route-contract-design.md), and [10-20 D2/D3 plan](2026-10-20-p7-d2-d3-dma-route-intents.md).
- Read repository `agent.md`. Work locally only; preserve all shared changes.
- D4-A artifact linkage and D4-B actual topology binding are distinct claims.
- No new runtime graph, CPU configuration, descriptor, feature or target operation.
- No dispatch from instance, component, directory or alias spelling.
- `read_master`/`write_master` are opaque aliases, never a rule for finding `dma.memory`.
- Existing runtime/decoder/artifact v1/v2 bytes remain unchanged when the new opt-in path is absent. Do not rewrite frozen evidence.
- Every new schema is closed; every accepted hash is recomputed; every unknown provider refuses.
- Bind once before startup. Additional topology guards participate in the existing pre-effect validator.
- No source/native implementation is performed by this planning task.
- During implementation, write focused tests first and capture expected RED, then GREEN. Do not run real/native test modules for this software slice.

## File ownership and milestones

| Milestone/task | Files | Responsibility |
|---|---|---|
| D4-A / 1 | Create `src/myfuzz/local_harness/dma_artifact_endpoint_links.py`; modify `src/myfuzz/local_harness/runtime_renderer.py` and `src/myfuzz/local_harness/driver_renderer.py` only for an opt-in fact collector/finalization facade; create `tests/local_harness/test_dma_artifact_endpoint_links.py` | Closed generation-issued physical endpoint links |
| D4-B / 2 | Create `src/myfuzz/scenario/dma_intent_topology_binding.py` and `tests/scenario/test_dma_intent_topology_binding.py` | Explicit declaration, route bijection, static policy matching |
| D4-B / 3 | Modify `src/myfuzz/scenario/runtime_path_contract.py`; extend Task 2 module/tests and `tests/scenario/test_runtime_path_contract.py` | Actual artifact/provider/target checks, optional guard and bind once |
| D4-B / 4 | Create `src/myfuzz/scenario/dma_binding_replay.py` and `tests/integration/test_dma_intent_binding_replay.py`; modify `src/myfuzz/scenario/session_runtime.py`, `src/myfuzz/integration/scenario_rfuzz.py`, `src/myfuzz/integration/scenario_rfuzz_live.py` | New outer envelopes, mandatory identity and two-phase replay |
| Acceptance / 5 | Extend `tests/integration/test_p7b_p7c_dma_route_intent.py`; create `docs/reports/p7-dma-intent-topology-binding-20261020.md`; update `docs/CURRENT_PROGRESS.md`, `docs/reports/README.md`, `docs/superpowers/plans/README.md` | End-to-end software boundary and honest scope report |

The `runtime_renderer.py`, `driver_renderer.py`, and `runtime_path_contract.py`
paths in the table retain their existing package directories. New unit fixtures
live in their owning test modules. Task 4 may introduce one explicit
`tests/scenario/dma_binding_fixtures.py` helper shared by these tests; do not
change unrelated production fixtures or rebuild real RTL.

## Task 1: D4-A generation-issued artifact role links

**Interfaces produced:**

```python
@dataclass(frozen=True)
class DmaLinkedRuntimeArtifact:
    artifact: LocalRuntimeArtifact
    def endpoint_links_document(self) -> dict: ...
    def document(self) -> dict: ...

def render_dma_linked_runtime(plan, structural, source_verification, *,
                              base_dir, provider_id) -> DmaLinkedRuntimeArtifact: ...
def parse_dma_artifact_endpoint_links(document, *, pointer='/endpoint_links'): ...
```

The parser returns an immutable object exposing `document()` and
`identity_sha256`. See the spec for exact keys; do not add logical aliases here.

- [x] Write `test_legacy_artifact_bytes_unchanged_without_link_opt_in` and `test_final_driver_artifact_has_complete_master_role_link`. Capture the ordinary final artifact document before invoking the linked facade and require exact inner-document equality afterward.
- [x] Write `test_unknown_provider_missing_role_or_wrong_template_refuses` and `test_runtime_stage_digest_cannot_replace_final_driver_digest`.
- [x] Run the RED gate:

```bash
PYTHONPATH=src python3 -m pytest -q tests/local_harness/test_dma_artifact_endpoint_links.py
```

Expected RED: missing new API or failing role-link assertion, not a native build.

- [x] Add only the registered `wishbone-dma-single-master.v1` issuer. Capture facts from `runtime_renderer` where the resolved `dma_master` is assigned to `mwb`; retain complete physical/member/range facts. The ordinary path uses no collector and emits exactly its previous document.
- [x] Use ordinary driver rendering, then finalize link hashes against the final artifact. The facade returns the new detached wrapper. Never attach new keys to the old runtime document or issue a certificate merely by finding an ID in an old artifact.
- [x] Strictly parse and revalidate provider contract, sorted link IDs/roles, master function/side, structural ABI, complete D2-compatible six-field template binding, runtime/C++ text hashes, and final artifact digest.
- [x] Run the command above for GREEN. Review that no link or status says a Runner or target is bound.

Representative assertions:

```python
assert linked.artifact.runtime_document == legacy.runtime_document
link = linked.endpoint_links_document()['links'][0]
assert link['endpoint_id'] == expected_resolved_master.endpoint_id
assert link['protocol_side'] == 'master'
assert {row['role'] for row in link['roles']} == set(DMA_MASTER_SHAPE)
assert 'read_master' not in {row['endpoint_id'] for row in linked.endpoint_links_document()['links']}
```

The last assertion uses the concrete wbdmac fixture whose actual endpoint is
`dma.memory`; it does not ban a legitimately declared endpoint with that text.

**Review gate:** D4-A was accepted independently. D4-B Task 2 now provides only the
detached declaration/preflight layer. Live binding and replay Tasks 3–5 remain
unimplemented; no historical adapter is recorded as already carrying the new
artifact credential.

## Task 2: D4-B immutable declaration and explicit bijection

**Consumes:** strict `PathWiring`, existing `PreparedRuntimePathContract`, and
D4-A link schema. **Produces:**

```python
class DmaIntentBindingError(ValueError):
    code: str
    pointer: str

def prepare_dma_intent_binding(wiring, prepared, *,
                               route_links) -> PreparedDmaIntentBinding: ...
```

`PreparedDmaIntentBinding` is frozen, retains canonical wiring/prepared/link
bytes, and exposes `document()` and `identity_sha256`. Its closed document and
route-link keys are exactly those specified in the design.

- [x] Add a small in-memory fixture using the existing typed read/write graph structure from `tests/scenario/test_runtime_path_contract.py`. Retain its original prepared document; use an exact-ID static intent and a matching D2 binding. Add a second fixture with two equal policies on different edges.
- [x] Write tests named `test_exact_id_route_links_preserve_existing_prepared_bytes`, `test_identical_policies_require_explicit_edge_keys`, and `test_duplicate_missing_or_extra_routes_refuse`.
- [x] Write strict schema/digest/pointer tests and exact tuple/range policy tests. Include a mismatch that keeps `list(range)` equal but changes `stop` or `step`.
- [x] Run RED:

```bash
PYTHONPATH=src python3 -m pytest -q tests/scenario/test_dma_intent_topology_binding.py -k 'declaration or exact_id or edge or policy or schema'
```

- [x] Implement the parser/declaration builder. Resolve graph edges only by explicit key, require selected typed kind/relation and exact data-flow orientation, require full route-set bijection, and compare every static/live policy field. Use existing canonical documents for accepted-value comparison; never compare range objects directly.
- [x] Match memory owner/resource and initial peripheral device-ID restrictions exactly; refuse unsupported scopes with the stable error codes in the spec.
- [x] Repeat the RED command for GREEN; require that `prepared.document()` and `prepared.contract.document()` are unchanged.

Representative assertions:

```python
before = prepared.document()
declaration = prepare_dma_intent_binding(wiring, prepared, route_links=links)
assert declaration.document()['prepared_runtime_paths'] == before
assert prepared.document() == before
assert {row['route_id'] for row in declaration.document()['route_links']} == expected_route_ids
```

## Task 3: actual endpoint-link validation and guarded topology bind

**Consumes:** Task 1 artifact links and Task 2 declaration.
**Produces:**

```python
def bind_dma_intent_topology(declaration, runner, *,
                            artifact_links) -> BoundDmaIntentTopology: ...

# Existing APIs gain a default-empty, nonserialized guard.
class PreparedRuntimePathContract:
    def bind(self, runner, *, path_ids=None, topology_guard=None): ...
```

`BoundDmaIntentTopology` exposes `runtime_compilation`, `document()`,
`identity_sha256`, and `validate_topology()`. The compiler's optional guard is
private frozen runtime state, not a runtime-v2 serialized field.

- [x] Write `test_exact_id_live_binding_uses_actual_artifact`, `test_explicit_alias_link_has_no_name_inference`, and `test_missing_artifact_link_or-provider_refuses`. Use fake transport methods that raise immediately if called; build typed artifact/link fixtures through the registered fact collector and finalizer rather than trusting handwritten role certificates.
- [x] In the alias positive, explicitly associate opaque aliases such as `opaque-input-17` and `opaque-output-29` with the same generation-issued master link and their declared operations. In a separate negative, supply `read_master` without a link and require refusal. Do not parse either alias string.
- [x] Add template/profile/selection digest mismatch cases, wrong actual master/role/backend cases, artifact replacement, copied-equal session/window/service/ledger cases, memory index changes, and unsupported target/subwindow cases. Also require each participating Runner key to equal the actual artifact plan's declared instance ID.
- [x] Run RED:

```bash
PYTHONPATH=src python3 -m pytest -q tests/scenario/test_dma_intent_topology_binding.py
```

- [x] Preflight all endpoint/target links against the actual Runner artifacts. Admit only registered session/provider combinations. Check six-field D2 bindings and actual artifact/plan/ABI/template values; an old artifact without Task 1 evidence refuses.
- [x] Thread `topology_guard` through the existing compiler and `CompiledRuntimePathContract.validate_topology()`. Snapshot actual session/artifact/plan objects and credential bytes. Call the existing bind once; let its existing configured callback run the composed topology check before target effects. Do not configure a second session callback or recursively call the compiled validator from the guard.
- [x] Build the closed `dma_intent_topology_binding.v1` credential; preserve original compiled runtime bytes. Keep memory and peripheral identities derived from their existing real object helpers.
- [x] Run GREEN:

```bash
PYTHONPATH=src python3 -m pytest -q tests/scenario/test_dma_intent_topology_binding.py tests/scenario/test_runtime_path_contract.py
```

Representative assertions:

```python
bound = bind_dma_intent_topology(declaration, runner, artifact_links=artifact_links)
assert bound.document()['tier'] == 'topology_bound'
assert bound.runtime_compilation.document() == expected_existing_compilation
bound.validate_topology()
assert native_commands == []
```

**Review gate:** Report separately which newly generated adapters passed. List
historical UART/PULP/ZipCPU/Caliptra artifacts without links as refused, not
implicitly migrated. A new supported master link does not add a target provider.

## Task 4: required outer save/replay envelope

**Interfaces produced by `dma_binding_replay.py`:**

```python
def encode_dma_bound_payload(payload_bytes, *, payload_kind, declaration,
                             binding_compilations) -> bytes: ...
def parse_dma_bound_payload(envelope_bytes, *,
                            expected_identity_sha256) -> DmaBoundPayload: ...
```

`DmaBoundPayload` is frozen and exposes exact `.payload_bytes`, its parsed
declaration and complete credential rows. The spec fixes all outer keys and
selection-ID sets. The expected outer digest comes from the verified report/run
manifest and is mandatory.

- [x] Write wrapper round-trip tests proving exact raw inner bytes are retained, including whitespace/newline differences. Test both payload kinds, canonical base64, unknown keys, duplicate/missing compilation entries, nested envelopes, corrupted payload and corrupted link/route credentials.
- [x] Write preflight tests with `factory = Mock(side_effect=AssertionError('factory reached'))`; mutate a credential, recompute its local digest and outer local digest, but retain a contradictory route set or the original expected external identity. Require refusal and `factory.assert_not_called()`.
- [x] Write tests that old online-plan and fresh-identity readers reject the new wrapper schema. Retain unwrapped legacy positive/byte-identity cases.
- [x] Run RED:

```bash
PYTHONPATH=src python3 -m pytest -q tests/integration/test_dma_intent_binding_replay.py
```

- [x] Implement strict envelope encoding/parsing in the focused new module. Reuse existing inner strict readers and `RuntimeEdgeIndex`; no filesystem/native operations belong in detached validation.
- [x] Add explicit new-schema dispatch to online saved-plan and fresh identity readers. Bound reports require the outer schema/digest and inner payload digest. Keep historical inner trace/plan hash meaning; do not rewrite reference traces to use the outer hash.
- [x] In `session_runtime.configure_runtime_paths`, accept a prepared binding declaration and artifact-link inputs only as an opt-in binding configuration; use Task 3 to replace the one existing bind call. Save the binding result through the new outer envelope. The ordinary path remains byte-identical.
- [x] In `ScenarioRfuzzExecutor`, carry the same optional prepared binding configuration through `_runtime_preflight`, save each required selection credential, and check full saved materials in `_install_runtime_replay_identity` before invoking a factory.
- [x] In `scenario_rfuzz_live.py`, validate outer report identity before ordinary inner identity validation; perform detached link/route checks first. After a fresh Runner exists, rebind and compare the full new credential before session/process startup. Missing required binding material never falls back to legacy.
- [x] Track the new production helper modules in the existing host/source identity inventories only for bound runs, so ordinary manifest bytes do not change merely because support was added.
- [x] Run GREEN:

```bash
PYTHONPATH=src python3 -m pytest -q tests/integration/test_dma_intent_binding_replay.py tests/integration/test_dma_master_route_replay_readers.py
```

Representative preflight test pattern:

```python
factory = Mock(side_effect=AssertionError('factory reached'))
with pytest.raises(DmaIntentBindingError):
    replay_bound_fixture(corrupt_envelope, factory,
                         expected_identity_sha256=original_identity)
factory.assert_not_called()
```

`replay_bound_fixture` is the test helper invoking the actual new dispatch path,
not a substitute verifier; define it in the owning integration test module.

## Task 5: D2/D3 boundary and evidence report

- [x] Add an in-memory integration positive carrying canonical D2/D3 route and binding rows into Task 2/3 using an existing typed runtime graph. Assert static route digest and the original prepared/runtime document digests are preserved.
- [x] Add the F6 boundary assertions below; run them RED before any implementation change needed for observability. Do not change the P7-C compiler to make the test green.

```python
assert compiled_f6['status'] == 'unsupported'
assert 'dma-route-live-topology-binding-required' in missing_codes
assert bound.document()['tier'] == 'topology_bound'
assert not new_runtime_graph_was_created
```

`new_runtime_graph_was_created` is a test spy on constructors/graph-build entry
points in the binding module; the binder must only retain the supplied graph.

- [x] Run the focused final software gate after all prior task gates pass:

```bash
PYTHONPATH=src python3 -m pytest -q tests/local_harness/test_dma_artifact_endpoint_links.py tests/scenario/test_dma_intent_topology_binding.py tests/scenario/test_runtime_path_contract.py tests/integration/test_dma_intent_binding_replay.py tests/integration/test_dma_master_route_replay_readers.py tests/integration/test_p7b_p7c_dma_route_intent.py tests/integration/test_route_intent_reader_boundaries.py
```

Expected: all selected software tests pass; no native driver, compiler, remote
command or real-run test is invoked. Record actual test counts, not estimates.

- [x] Write the report with actual RED/GREEN commands/results, D4-A versus D4-B status, supported issuer/session pairs, every refused historical adapter, exact identity preservation, and explicit remaining CPU/transfer/IRQ/F6 gaps.
- [x] Update progress/report/plan indexes using those exact boundaries. Do not mark P7/P8 complete or report `runtime_observed`/`replay_verified` from software binding tests.
- [x] Review scoped changes without staging or committing. Leave all unrelated shared work intact.

## Compact test matrix

| Group | Minimum positive | Minimum negative |
|---|---|---|
| Artifact issuance | Actual resolved master -> emitted backend roles -> final driver artifact | Missing/wrong role, template or final hash; unregistered issuer; old artifact |
| Exact endpoint | Static/runtime/artifact IDs equal with complete evidence | Same text but wrong role/artifact/provider |
| Explicit alias | Opaque alias declared against an admitted physical master | Missing association, swapped operation/link, conventional alias text without evidence |
| Route bijection | Existing typed read and write edges mapped explicitly | Missing/extra/duplicate edge; equal policy ambiguity; wrong orientation |
| Policy/target | Exact window or full shared-memory region | Subwindow, independent device ID, permission change, tuple/range collision |
| Live topology | Same real sessions, artifact, window, memory/service/ledger | Equal-object replacement, identity mutation, overlap or memory-index change |
| Saved material | Both wrapper kinds and fresh equivalent object rebind | Corruption/omission/unknown schema before factory; fresh credential mismatch before native startup |
| Compatibility | Old v1/v2 bytes and readers unchanged | Old readers reject new wrapper; bound run cannot strip wrapper requirement |
| Capability | Credential tier `topology_bound`; P7-C F6 remains unsupported | No CPU program, descriptor, graph, transfer/IRQ claim or observed/replay tier promotion |

## Completion and outstanding boundaries

- [x] D4-A issuance accepted independently with complete role facts and final artifact identity.
- [x] D4-B exact-ID and explicit-alias paths accepted only with D4-A evidence.
- [x] Full bijection and composed topology mutation guard verified.
- [x] Corrupt bound payloads rejected before Runner factory; fresh mismatch rejected before native startup.
- [x] Legacy identities preserved; unknown new envelopes rejected by old readers.
- [x] Report lists unsupported artifacts/providers/target shapes and keeps F6/P7/P8 open.

D4-A Task 1 and D4-B Tasks 2–5 have software implementation and review
coverage. The focused final software gate recorded 166 passed and 30 subtests.
Task 3/5 grants only a software `topology_bound` credential; Task 4 preserves
that credential across saved/replay envelopes. Do not call this a runtime DMA
transaction or an F6 acceptance. P7-C F6, P6/P7/P8, and the six-CPU/four-IP
objective remain open. Preserve the shared dirty worktree.
