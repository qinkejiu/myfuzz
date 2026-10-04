# Local Harness V2 Declarative Tuning: Configuration Phase

Based on main `48c07bf6fcdf0efda9a28b8d021a585692d428a8`, the explicit v2 request parser and pure profile/binding validator now exist. This phase does not generate or apply execution strategies. Existing v1 six-field construction, serialization and validation tests remain unchanged. LocalHarnessRequestV2 is a separate frozen type; the current planner refuses it with `local-harness-request-required`, preventing ignored tuning from reaching existing runtime paths.

## Interface and Accepted Scope

Import `load_local_harness_request` / `LocalHarnessRequestV2` from `myfuzz.local_harness.request`, and `validate_local_harness_tuning` from `myfuzz.local_harness.tuning`.

V2 requires exactly the common six fields with schema_version `local_harness.v2`, plus `tuning`. Tuning strictly parses endpoint_policies, optional_signals, reset_policies, irq_delivery, boot, environment_bindings and peer_bindings using closed field schemas. Unknown fields, invalid enums, duplicate semantic identities, bool-as-int, out-of-range timings, unbounded tokens and expression/code strings refuse. List rows normalize by semantic identity, absent lists become empty, and serialized documents are fresh copies.

Currently accepted configuration validation:

- Reset assert/release timings for existing bound reset domains, with sequence dependencies refused.
- IRQ delivery selection agreeing with a real bound output and a unique profile level/pulse declaration; pulse width, polarity, source clock domain and bit position are checked. This validates the declared contract, not a runtime pulse capture implementation.
- Existing external pin inputs mapped to explicitly registered source IDs, only when the caller provides a complete upstream-bound input set and the requested target is not owned upstream. The existing full-port disposition validator must prove that these bits are already environment inputs.

Endpoint template variants, all optional signal policies, boot and peer selection parse but refuse capability validation. There is no verified registry/ownership/render contract for them yet. In particular, bound endpoint plus same-bit constant port_action currently violates the existing disposition rules; those rules were preserved. Protocol identity, physical selectors, reset polarity/synchrony, parameters and IRQ shape remain profile facts, rather than unchecked request overrides.

`validate_local_harness_tuning(tuning, profile=..., binding=..., registered_source_ids=..., bound_inputs=...)` rebinds the actual profile against full physical facts, verifies binding equality and source revision/top consistency, checks complete port ownership, and returns immutable evidence with `status=validated_configuration_only` and `runtime_effective=false`. It does not perform source-lock verification; the separate source gate remains necessary before eventual artifact acceptance.

V2 request SHA includes common request fields and canonical tuning. Validation SHA includes tuning, binding hash, actual profile contract hash and explicit source/ownership context. These are configuration identities, not executable artifact/replay identities.

## Evidence

- Plan committed first: `783fed9`.
- TDD observed missing v2 parsing failures, then missing pure validator failures, a missing request identity property failure, and an accepted unknown IRQ clock domain before implementing those behaviors.
- `PYTHONPATH=src:. python3 -m unittest tests.local_harness.test_request tests.local_harness.test_tuning -q`: 29 tests passed, including 6 unchanged v1 tests and 23 new parser/validation tests.
- All local_harness request, tuning, plan, renderer and source-lock tests: 64 passed. The isolated worktree's code/tests were used with test ROOT/SCRIPT constants pointed at `/home/qinkejiu/myfuzz` to read existing submodule checkout bytes. No source symlinks, network access or full integration-suite exclusions were involved.
- Actual PULP GPIO profile elaboration and binding accepted reset domain `sys_rst` and source `gpio_input` mapped to `gpio.pins:in` with `bound_inputs=set()` explicitly supplied. That profile has no IRQ declarations; this smoke therefore proves reset/environment configuration only. IRQ validation was exercised with typed fixture facts for level/pulse, wrong delivery, missing pulse width and out-of-width bit.
- PULP v2 request SHA256: `5e2ce972d52175bbe470da24898bafacb3c1a47ebfc5ac4c0af0bc2d5e863ddf`.
- PULP validation SHA256: `024c6ba5a40ddc59e4fb4a2252fd3eec459b8c47ca8e74809ee5faa7f7487365`.

No modifications to plan.py, renderer.py, runtime_renderer.py or existing source/profile/RTL files. No runtime strategy, Generated level or RTL operational level is promoted by this change. No push.
