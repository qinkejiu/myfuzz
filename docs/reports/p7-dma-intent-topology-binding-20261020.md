# P7-D4-B live DMA topology binding

Date: 2026-10-20

## Completed software scope

Added `bind_dma_intent_topology(...)` and a closed `dma_intent_topology_binding.v1`
credential. It validates a Task 2 declaration against newly generation-issued
D4-A endpoint links, actual generated Runner artifacts, the explicit typed route
set, and the existing runtime compiler. Each participating Runner session-map
key must equal the actual artifact's `plan.request.instance_id`; this applies
to DMA initiators and persistent-memory or peripheral targets. The guard repeats
that check after bind.

The binder preflights every route and target before it calls the existing
`PreparedRuntimePathContract.bind` exactly once. Its nonserialized topology guard
is attached to the existing compiled validator and session callback. It snapshots
session/artifact/plan/structural objects and link document identity/bytes, and
rejects equal-object replacement. The original runtime compilation v2 document
is byte-equivalent with and without the guard.

Only explicit endpoint aliases are accepted. Tests link opaque read/write aliases
to the same generated physical `dma.memory` master and declared operations;
`read_master` or `write_master` text without a link refuses. Registered DMA master
provider is the generated single-master Wishbone DMA session. Tested peripheral
target is a newly generated OpenTitan UART with its adapted endpoint and complete
template binding. Wishbone UART target admission has no positive fixture in this
slice.

## Verification

TDD review fix added a negative matrix for artifact instance mismatch under the
`dma`, `cpu`, and `uart` Runner keys. Positive fixtures render distinct generated
artifacts for those keys through the registered collector/finalizer; no positive
artifact is created by editing or rehashing its runtime identity.

Root verification after independent review:

```text
PYTHONPATH=src python3 -m pytest -q tests/scenario/test_dma_intent_topology_binding.py tests/scenario/test_runtime_path_contract.py
104 passed, 30 subtests passed in 7.67s
```

Independent Task 3 review found an instance-key gap. The implementation now
checks the actual `plan.request.instance_id` before binding and in the guard;
fresh re-review found no Critical, Important, or Minor findings. Scoped
`git diff --check` and explicit trailing-whitespace scans passed.

## D4-B Task 4: required save/replay envelope

The opt-in bound path now writes and reads the versioned outer envelope while
preserving the exact inner payload bytes. Detached readers validate the
expected outer identity and embedded declaration/link/route credentials before
Runner construction; a fresh Runner is rebound and its complete credential is
compared before startup. The ordinary unwrapped path retains its historical
identity and bytes. The focused regression covers corrupt/unknown envelopes,
factory-before-validation ordering, fresh rebind, and legacy reader boundaries.

## Task 5: generated D2/D3 route to the existing typed topology

The integration test generates the ZipCPU `wbdmac` DMA route and binding rows
through D2, compiles them through D3, and carries those exact rows into the
existing Task 2/3 typed read/write graph fixture. It checks the D2 route digest,
the static binding digest, the full prepared document digest, and runtime
contract digest. The binding uses an already-created
`PreparedRuntimePathContract`; constructor spies and an identity assertion
prove the binder passes that exact object to `bind` without constructing a new
runtime graph. Explicit D2 target template identity is recomputed from the
actual generated OpenTitan UART artifact and checked against its physical
template binding.

The F6 output from P7-C remains `unsupported` with
`dma-route-live-topology-binding-required`; its compiled graph and contract
contain no DMA transfer edge. The D2/D3 binding example uses the route wiring
without a resource supplement; the existing separate supplement-merge test
continues to cover that path. No P7-C behavior was changed to enable F6.

D4 has a positive peripheral target fixture for the generated OpenTitan UART.
The PULP GPIO provider is separately implemented and has a real native/fresh
single-word DMA report, but `GeneratedPulpGpioSession` is not yet admitted as a
D4 target here. Extending D4 must verify the registered PULP provider identity
and observation contract; the existing PULP run is not implicitly promoted to
a D4 credential.

Review first exposed a masked graph reconstruction: the test had replaced
`PreparedRuntimePathContract.from_document`, so constructor spies did not
observe production behavior. Removing that patch produced the expected RED
(the no-new-graph assertion failed); in-memory declarations now retain the
validated prepared object, and the parser checks its full canonical document
against the embedded bytes before reuse. A dedicated negative rejects a
different prepared object before binding.

Final software gate after review and the explicit identity assertion:

```text
PYTHONPATH=src python3 -m pytest -q tests/local_harness/test_dma_artifact_endpoint_links.py tests/scenario/test_dma_intent_topology_binding.py tests/scenario/test_runtime_path_contract.py tests/integration/test_dma_intent_binding_replay.py tests/integration/test_dma_master_route_replay_readers.py tests/integration/test_p7b_p7c_dma_route_intent.py tests/integration/test_route_intent_reader_boundaries.py --tb=short
166 passed, 30 subtests passed in 44.02s
```

The focused gate is software-only; it does not run a native driver, transport,
DMA transaction, remote command, or real-run test. Independent review found no
Critical or Important issue. The new Task 5 test also passed alone after the
graph-retention fix; the peripheral fixture regression passed 4 cases.

## Boundaries

This is a software topology credential. It does not run a native transport,
perform a DMA transaction, configure DMA from a CPU program, prove data movement,
observe completion IRQ/ISR, or establish fresh native-run replay. Historical
initiator aliases without new generation-issued endpoint links remain refused;
no historical evidence is implicitly migrated.

D4-B Tasks 4–5 have software implementation and review coverage; this does not
establish a native DMA transaction or fresh native replay. P7-C F6 remains
unsupported. P6/P7/P8 and the six-CPU/four-IP objective remain open.

See the [D4 design](../superpowers/specs/2026-10-20-p7-dma-intent-topology-binding-design.md),
[implementation plan](../superpowers/plans/2026-10-20-p7-dma-intent-topology-binding.md),
and [current progress](../CURRENT_PROGRESS.md).
