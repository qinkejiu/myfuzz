# Task 6 independent review I1–I3

## Changes

- Reject unknown non-`x-` keys at plugin, field, action, channel relation and temporal rule levels. Action, relation and temporal kinds use closed supported vocabularies. Existing `x-` annotation acceptance and capability extension handling remain compatible.
- CompiledProtocol retains complete channel relations and capability limits. ProjectionPlan retains the compiled contracts and diagnostics; both participate in its hash and remain available through the depaware artifact's projection_plan.
- Temporal projection bounds use the minimum of the action bound, all rules sharing the antecedent, and capability max_wait_cycles. The same reduction applies to synthesized rule-only gates.
- Byte-enable fields may declare semantic_role=byte_enable. Compilation checks their evaluated width against data_width/8. Existing arithmetic `data_width / 8` and `data_width // 8` declarations are recognized structurally for compatibility; arbitrary equal-width fields are not classified by width alone.
- Mapped canonical byte enables force all lanes enabled in Python projection and the existing depaware RTL generation path. Missing destinations produce explicit plan diagnostics without inventing protocol ports.
- Wishbone catalog expectations now follow the main thread's classic-only metadata: stall_supported=false and optional stall field. No plugin JSON or RTL was edited here.

## Verification

Regression-first run reproduced unknown-key/kind acceptance, missing compiled metadata, floor-division omission and temporal overwrite (9 failed assertions and one missing-attribute error).

Final checks:

```text
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest discover -s tests/protocols -q
63 tests OK
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest discover -s tests/harness -q
66 tests OK
```

New regression suite covers schema keys/kinds, extension acceptance, metadata hashing, both rule orders, capability minimum, rule-only gates, equivalent width expressions, explicit semantic role validation, forced canonical values and APB3/OBI missing-port diagnostics.

## Functional boundary

Channel relations and non-projection capabilities are retained as adapter obligations, not implemented as new cross-channel state machines by this patch. Projection diagnostics explicitly state this boundary. Projection enforces bounded gating, declared transfer-size constants and mapped full-byte enables; its gates are bounded sample shaping, not proof that a DUT handshake completes within a deadline. APB3/OBI without byte-enable destinations require canonical adapter enforcement, which this scoped patch does not implement or claim to validate. Top-level composition and RTL integration remain with the main thread. `x-` annotations outside capability_limits are accepted as before but are not executable constraints.

Only the requested protocol/harness source files, related catalog/regression tests and this independent report are included. User-owned third_party and task-2 report are untouched.
