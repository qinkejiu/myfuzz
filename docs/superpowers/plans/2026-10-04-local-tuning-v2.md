# Local Harness V2 Declarative Tuning Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Parse a strictly versioned local request and validate declarative tuning against existing bound source/profile facts without claiming runtime integration.

**Architecture:** Keep the v1 dataclass and document unchanged. Add a separate frozen LocalHarnessRequestV2 and immutable LocalHarnessTuning records. A pure validator rebinds the supplied profile to the supplied physical facts, checks exact binding equality, and checks timing, physical input constants, IRQ semantics and environment source ownership. Unavailable template, boot and peer contracts fail closed. Validation produces a canonical document/hash that incorporates the binding and explicit ownership context, but no generated plan/session consumes it yet.

**Tech Stack:** Python 3.12, dataclasses, unittest, existing bind_profile.

## Global Constraints

- Do not modify plan.py, renderer.py, runtime_renderer.py or existing runtime contracts.
- V1 six-field parsing/output/errors remain intact; v2 requires tuning and uses a separate type that planner rejects.
- Strict schemas reject extra/missing fields, boolean-as-integer, duplicate identities and code text.
- No source/parameter/protocol overrides, IRQ fabrication or output drive.
- Environment tuning requires explicit registered source IDs and explicit complete bound-input context; missing context refuses environment tuning.
- Tuning is parsed/validated only and has no runtime effect in this milestone.

## Allowed Shapes

V2 contains exactly the six v1 fields, schema_version=local_harness.v2, and tuning.
Tuning permits only endpoint_policies, optional_signals, reset_policies, irq_delivery, boot, environment_bindings, peer_bindings. All lists normalize by semantic identity; absent lists become empty. Boot is absent or one record.

- endpoint_policies rows: endpoint_id/template_id/template_version/variant_id/max_outstanding (bounded 1..1024); no template capability registry exists yet, so nonempty rows refuse validation.
- optional_signals rows: endpoint_id/role/policy/value?; policy drive_constant requires unsigned integer value; template_default has no value and refuses validation until a template exists. Constant tuning must equal an existing profile-declared physical constant for the exact bit segment.
- reset_policies rows: domain/assert_ticks/release_ticks, bounded 1..1024 / 0..1024; domain must exist in bound resets.
- irq_delivery rows: endpoint_id/role/delivery; delivery follow_level or capture_pulse_event, agreeing with the profile level/pulse trigger and a bound output.
- boot: endpoint_id/entry_address (unsigned integer); refused until a boot template capability contract exists.
- environment_bindings rows: endpoint_id/role/source_id; only bound input roles of external_pins endpoints, registered source ID, and no explicit upstream-bound input; profile constant and functional protocol ownership cannot be replaced.
- peer_bindings rows: endpoint_id/peer_id; refused until registered peer capability contracts exist.

### Task 1: V2 Parsing and Canonical Form

**Files:** Create src/myfuzz/local_harness/tuning.py; modify src/myfuzz/local_harness/request.py; create tests/local_harness/test_tuning.py.

**Interfaces:** load_local_harness_request(document) returns LocalHarnessRequest or LocalHarnessRequestV2. load_local_harness_tuning(document) returns frozen LocalHarnessTuning; document() returns fresh normalized JSON values; identity_sha256 hashes that canonical document.

- [ ] Write v2 request tests; demonstrate missing v2 support fails. Test unchanged v1, required tuning, invalid extra fields at every depth, duplicate row identities, integer/enum bounds, immutable/fresh document and list-order canonical equivalence.

```python
v2 = {**GOOD, 'schema_version': 'local_harness.v2', 'tuning': {}}
request = load_local_harness_request(v2)
self.assertNotIsInstance(request, LocalHarnessRequest)
self.assertEqual(load_local_harness_request(request.document()), request)
```

- [ ] Run `PYTHONPATH=src:. python3 -m unittest tests.local_harness.test_request tests.local_harness.test_tuning -q` and record the expected missing v2 failure.
- [ ] Add frozen record tuples, exact field schemas, sorted canonical document and SHA; dispatch v2 through unchanged v1 validation of the common fields.
- [ ] Run the same command; require parser tests passing.

### Task 2: Pure Bound-Fact Validation

**Files:** Extend src/myfuzz/local_harness/tuning.py; extend tests/local_harness/test_tuning.py.

**Interfaces:** validate_local_harness_tuning(tuning, *, profile, binding, registered_source_ids=None, bound_inputs=None) -> ValidatedLocalHarnessTuning. Context keys use (endpoint_id, role) tuples. Rebind profile against binding.facts before accepting it. Return identity_sha256 and document with explicit parsed_only/no runtime effect status.

- [ ] Construct a tiny in-memory profile with scalar reset, external pin input, declared constant configuration input and level/pulse IRQ outputs; bind against matching PhysicalFacts. Assert successful timing, exact constant, matching IRQ and unbound registered environment tuning.
- [ ] Assert wrong direction/role, constant overflow or nondeclared value, unknown reset, incompatible IRQ, absent pulse width, stale binding, missing ownership context, unknown source, bound input and unavailable template/boot/peer contracts refuse.
- [ ] Run validator tests before implementation; observe missing validator failure.
- [ ] Implement validation with `bind_profile(profile, binding.facts)` equality, profile interrupts and port actions; no DUT/runtime generation.
- [ ] Run request/tuning tests and relevant local_harness regressions, preserving planner mutation tests. Real regression fixtures can use existing source checkouts via module ROOT overrides, never source symlinks.

### Task 3: Evidence and Commit

**Files:** Create docs/reports/local-tuning-v2-20261004.md; modify only local_harness/__init__.py exports if needed.

- [ ] Record exact test counts, command context, accepted/rejected fields, canonical identity evidence and lack of runtime integration.
- [ ] Run `git diff --check`, verify prohibited files unchanged, commit with `git commit -m 'feat: parse and validate declarative local harness v2 tuning'`; do not push.
