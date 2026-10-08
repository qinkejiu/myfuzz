# P2 pin8 native IRQ receipt to RVFI trap relation (2026-10-07)

## Evidence boundary

`Pin8TrapRetirementCertificates(require_native_receipts=True)` now requires the
real CPU pre-edge sample and native take to name the same CPU step and parsed
`STEP_CPU` receipt as the source-certified runner take. It then requires one
sample for every consecutive CPU command through the first retirement, with
stable execution and reset epoch, consecutive command sequence and local tick,
no intervening sampled take, and the retirement's complete post-edge receipt
equal to the final sample's command identity. A second observed take, reset,
flush, missing sample, changed RVFI order, or incompatible first retirement
cancels the relation. Malformed native references fail closed.

The duplicate fields on the initial sample and native take must agree,
including actual pre/post IRQ input, pre/post RVFI notifications, decision
probe, command identity, outer execution ID, and reset/source epochs. Every
intermediate sample and the final retirement must retain that outer execution
and epoch identity. A follow-up adversarial review found this missing check;
mutations to event 4,699's input or notification, event 4,698's epoch or
execution, an intermediate sample's execution, and event 4,911's execution
were observed incorrectly retaining the first relation before the fix.

The result is deliberately named
`native_receipt_bounded_architectural_trap_relation` and retains
`explicit_source_token_on_retirement=false`. The `take_key` is an ID assigned
by the host after observing the controller decision. It is not present in RVFI
and is not carried to the retirement. These checks narrow an architectural
association; they do not prove exact hardware source identity across the five
CPU ticks, nor any ISR data path or full pin8→GPIO A propagation chain.

The original weaker mode remains available for the older trace and preserves
its earlier report's scope. Strict mode grants zero relations on that trace
because it has no native CPU receipts.

## Saved real RTL audit

The unmodified 24,508-event real RTL trace is
`runs/current-dataflow-p2-native-gated-20261007-online/online_final_trace.json`,
SHA-256 `f5af69ccf92ee3bae8fa26df3d0a916733e768815169f7449a34cffaabc799e2`.
Its original frozen-source online run, 18/18 complete cases, and full fresh
replay are documented in
[the native receipt report](current-dataflow-p2-native-irq-sampled-receipt-20261007.md).
This follow-up evaluates saved RTL events with a new read-only consumer; it is
not a new RTL execution or a new fresh replay of the changed working tree.

| Source event | Native take | Runner take | RVFI retirement | Gap in CPU ticks |
| ---: | ---: | ---: | ---: | ---: |
| 1 | 4,699 | 4,701 | 4,911 | 5 |
| 3 | 11,984 | 11,986 | 12,192 | 5 |
| 5 | 17,014 | 17,016 | 17,222 | 5 |
| 6 | 21,996 | 21,998 | 22,204 | 5 |

The real-trace fixture mutates receipt IDs, sample references, CPU step joins,
the accepted post-edge notification, duplicate take fields, outer execution
and epoch identities, an intermediate sample, competing take decision,
retirement command scope, and malformed references. Each damaged first
relation is rejected. The earlier non-native trace is also rejected by strict
mode.

## Verification

```bash
PYTHONPATH=src:. pytest -q \
  tests/scenario/test_pin8_native_trap_relation.py \
  tests/scenario/test_pin8_trap_retirement_certificates.py \
  tests/scenario/test_pin8_cpu_irq_certificates.py \
  tests/local_harness/test_cpu_native_irq_receipt.py \
  tests/local_harness/test_cpu_native_retirement_receipt.py
```

The new tests were observed failing before implementation for the missing
strict mode, then for an intermediate take and a noninteger notification;
the malformed-reference case reproduced a `TypeError` before correction.
Final result after the follow-up fix: **52 passed, 21 subtests passed**. `git diff --check` and
`compileall` exited 0.
