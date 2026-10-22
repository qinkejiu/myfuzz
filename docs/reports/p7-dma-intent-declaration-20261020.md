# P7-D4-B detached DMA intent declaration

Date: 2026-10-20

## Completed

Added a frozen, canonical PreparedDmaIntentBinding declaration and
prepare_dma_intent_binding() for detached preflight. It verifies a complete
explicit bijection between static PathWiring route intents and selected typed
DMA_MASTER_TRANSFER / dma_master_route edges. Each association carries static
route ID, rule/prerequisite indices, runtime route digest, operation, endpoint
IDs, declared D4-A provider/link summary, and retained six-field template
binding. No route is matched by policy, name, address, order, or first-master
guessing.

The declaration compares every supported policy field. Memory targets require
the exact owner/resource, full region aperture, and permissions. Peripheral
targets require the exact component/device/endpoint window and supported
aperture. Static tuple-value lists are compared with ordered live tuple values;
range start/stop/step are compared exactly. Unsupported or ambiguous shapes
refuse with stable codes and JSON pointers.

The strict reader rejects non-JSON container shapes before normalization,
validates closed keys and digests, and round-trips the embedded wiring and
prepared documents. Preparation uses the caller's existing prepared object;
the strict reader may deserialize its embedded graph only to validate the
serialized declaration. This task does not generate or search a runtime graph.

## Verification

- TDD RED: the task's focused pytest command initially failed during collection
  because the new module did not exist.
- Final focused software gate, independently rerun:
  PYTHONPATH=src python3 -m pytest -q
  tests/scenario/test_dma_intent_topology_binding.py -k
  'declaration or exact_id or edge or policy or schema'
  Result: 45 passed in 0.35s.
- Independent task review: Approved after fixing strict container normalization
  and deterministic refusal-field order; no Critical/Important findings.
- Scoped git diff check passed. New code/test files have no trailing whitespace.

## Remaining scope

This report records the detached declaration/preflight layer at Task 2. The
later Task 3 implementation now validates D4-A credentials against live
artifacts/sessions, binds the Runner topology, and installs a mutation guard;
see the [Task 3 report](p7-dma-intent-topology-binding-20261020.md). This
declaration layer itself does not execute or replay DMA. D4-B save/replay
Tasks 4–5 remain open. P7-C F6 stays unsupported; P6/P7/P8 and the
six-CPU/four-IP objective remain open.
