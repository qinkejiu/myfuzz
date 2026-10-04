# Local harness source fact planner evidence — 2026-10-04

Status: the `local_harness_plan.v1` fact-bound planning stage is verified for one pinned component per request. This is a fact-bound plan only. No wrapper RTL, C++ driver, session, SoC fabric or runtime status is generated; Generated, RTL operational and Cross-component accepted status have not been established.

Requests used `reset_assert_ticks=8`, `reset_release_ticks=8`, and `max_wait_cycles=16`. CVE2 used instance `cpu_0`; PULP GPIO used instance `gpio_a`, with their existing component profiles.

| Component | Physical ports | Plan port records | Classified bits | Ordered source files |
| --- | ---: | ---: | ---: | ---: |
| cv32e20 | 70 | 70 | 1308 | 28 |
| pulp_gpio | 17 | 17 | 341 | 1 |

Both real source elaborations return `PhysicalFacts.selection == "all"`. Every physical bit receives exactly one disposition. The planner preserves each ledger record's physical direction, span, endpoint, role, drive classification, evidence and reason, replacing only its destination with a local destination. PULP GPIO exposes `gpio_in` through the declared `gpio.pins/in` role as an environment pin. Environment classification alone neither creates a driver nor independently randomizes values. Existing disposition reasons retain their original SoC vocabulary as provenance; local ownership is recorded by the mapped target.

CVE2 source revision: `git:d079e8c8e6a08b330940ae123876ba0612bec18d`.
Source content hash: `sha256:afe5ca029cc2ba2078bb7524475dc8061c32f88bcb91e197ae2861512c00b338`.
Profile file SHA-256: `18ef425486107690d2fb92bb80141cbfab4013b05768c8c2a5ee706fe223d7ec`.
Plan SHA-256: `22ccf552ca300865c0c5f757012eafff124241f6985cfeaf49bd53bd5ad46397`.

PULP GPIO source revision: `git:f82caeb7f7d89427f05e9af5ed31e0675efe0d83`.
Source content hash: `sha256:bde1f2c536e833582ab80faf74f8e56394aeb2af8cf6528a9452c34daa1da456`.
Profile file SHA-256: `2268967fa909658fbc079fc41112a10bba88e7484909153cbc1a5a1b222a0b56`.
Plan SHA-256: `95c4294c99effe3abe098937e59a5fe7aa65d19199e8679d3d2f294bb89b0a6a`.

Plan hashes use UTF-8 bytes of `json.dumps(plan.document(), sort_keys=True, separators=(",", ":"))`, without a trailing newline. The document includes the source closure in frontend order, source and profile file hashes, timing, actual protocol endpoint IDs and sorted port records. Repeated CVE2 elaborations produced identical documents.

Validation command:

```bash
PYTHONPATH=src:. python3 -m unittest tests.local_harness.test_request tests.local_harness.test_plan -q
```

Actual result: 14 tests passed (`Ran 14 tests`, `OK`). The first planner test run failed at import because the planner export did not exist, before implementation. Negative tests verify missing profiles, profile symlink escapes, unknown destination refusal and full-bit ledger refusal for removed or duplicated CVE2 port actions. The real selected-only Ibex profile is rejected with `full-top-required`; this coverage limitation is never accepted as full-top evidence. `git diff --check` also passes.

The planner retains frozen references to existing profile/facts/binding records and an immutable disposition tuple. It does not modify the existing fixed source list or older session/evidence identities. Binding environment inputs to real upstream outputs and implementing local protocol owners remain work for the rendering/runtime milestone.
