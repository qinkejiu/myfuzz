# Generated local scenario identity and reset contract

Base: `039baf3`. Scope: Task 5 preflight/reset/replay identity only; runner event and pulse logic unchanged.

Generated sessions retain `generated_local_session_identity.v1` including full runtime artifact and canonical build identity. Runner identities containing these sessions use `scenario_manifest_identity.v2` and `scenario_harness_host_sources.v2`. V2 source closure contains the unchanged legacy host closure plus each generated build's authenticated nongenerated inputs, including actual generator/Python dependencies, C++ headers, RTL includes, adapter and profile bytes. Legacy `scenario_host_sources.v1` retains its exact 34-file enumeration, ordering and verification.

ScenarioManifest preflight accepts only the explicit generated CPU/GPIO session classes. It reconstructs the request from the runtime plan, verifies local sources, regenerates the structural wrapper/runtime top/driver and requires exact artifact and build identity equality. It performs no RTL launch or binary build. Generated packages cannot omit host identity or substitute v1 host identity.

Per-component reset timing format:

```json
{
  "schema_version": "generated_local_reset.v1",
  "artifact_digest": "<runtime artifact SHA-256>",
  "driver_sha256": "<generated C++ SHA-256>",
  "hold_cycles": 8,
  "release_cycles": 8
}
```

The hashes and counts must match the authenticated regenerated driver. READY's measured asserted/released counts continue to be checked by the generated session wire parser after startup; these transient measurements are excluded from stable replay identity. Legacy literal-loop wrapper reset validation remains intact. The published runtime manifest JSON schema accepts both record variants; Python preflight additionally enforces source/build equivalence.

## Evidence

Tests first observed runner identity v1 instead of v2, then a missing-host-record acceptance, and a JSON schema rejection of v2; each failure preceded its implementation fix.

```sh
PYTHONPATH=src python3 -m pytest -q \
  tests/scenario/test_generated_local_contract.py \
  tests/local_harness/test_generated_replay_identity.py \
  tests/scenario/test_contracts.py \
  tests/scenario/test_host_source_identity.py
```

Result: **39 passed, 12 subtests passed in 36.52s**. Tests cover genuine GPIO source-backed artifact regeneration, reset count/hash tampering, nested artifact/build tampering, missing host v2, legacy 34-file preservation, generator-only drift, wrong measured READY counts, published schema validation, replay profile/driver/ABI/adapter identity changes rejected before begin_case, and exclusion of transport execution UUID from stable identity.

No real RTL process is needed for this preflight task. CPU class admission is explicitly `myfuzz.local_harness.cpu_session.GeneratedCve2Session`; its module and runtime integration are supplied by the parallel CPU task. Task 5 command-internal tick/pulse evidence is supplied separately. V2 manifests intentionally depend on exact current build toolchain and host bytes, so a different toolchain or semantic source closure requires a new manifest.
