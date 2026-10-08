# P2 native IRQ to RVFI source attribution audit (2026-10-07)

## Result and boundary

The existing four pin8 native take to RVFI relations remain **bounded architectural
relations**, not exact source identity certificates. This turn did not add a
hardware token and did not run new RTL. The saved real Ibex plus dual GPIO
trace was re-audited read-only. The strict consumer now rejects a native CPU
post notification on any intermediate step when it differs from that step's
measured CPU output, has the wrong fields or width, or changes observation
contract. It still reports `explicit_source_token_on_retirement=false`.

The source identity at `cpu_external_irq_taken` includes the host-generated
`take_key`. Its parsed `STEP_CPU` receipt establishes the physical pre-edge
input and controller decision. The later `cpu_retire` contains RVFI `intr=1`
and the parsed command receipt for that retirement step; it contains no
source serial captured at the interrupt decision. The five-step sequence and
fixed handler PC do not supply that missing hardware relation.

## Hardware feasibility finding

In the pinned `ibex_core.sv`, the controller IRQ PC decision sets
`rvfi_set_trap_pc_d`, which is registered into `rvfi_set_trap_pc_q`.
`rvfi_intr_d` uses that state on the first handler instruction, and
`rvfi_stage_intr[0]` captures it on `rvfi_id_done`; subsequent RVFI stages
carry it on their own completion conditions. The current wrapper exports the
RVFI bit but no parallel decision identity. A host side counter sampled at
take and read at retirement would merely reproduce the existing temporal
inference, especially if a higher priority trap, flush, or second decision
intervenes.

An exact certificate needs a passive RTL sideband that assigns a nonzero
serial at the same accepted external IRQ decision edge, holds or invalidates
it under the **same** `rvfi_set_trap_pc` conditions, captures it with the
handler instruction under `rvfi_id_done`, advances it with each actual RVFI
stage completion, and exports it beside `rvfi_valid/intr`. The host must
authenticate matching take and retirement serials from complete parsed
receipts, plus reset epoch and nonwrap behavior. Tests must cover superseding
NMI/debug, re-entry, stalls, flushes, and reset. This requires revising the
Ibex RVFI wrapper and profile, elaborating the new ports, updating the
profile/closure/source hashes in `ibex_rvfi_contract.py`, and freezing a new
source and build identity. Simply adding a field to `cpu_retire` in Python
would not prove hardware lineage. No upstream Ibex source needs to be edited
if the observer can mirror the existing state and stage enables correctly;
that equivalence still needs RTL tests and source review.

## Test-first adversarial guard

On the saved trace, event 4,744 is an intermediate native sample between
the first take and retirement. Changing its `notification_post.rvfi_intr`
from 0 to 1 retained retirement 4,911 before the fix. The new test was run
first and failed with the relation still present. The strict consumer now
compares every declared native post notification field with the paired CPU
step output, using strict integer widths and an unchanged contract. Tests
also damage `rvfi_ext_irq_valid`, remove a notification field, inject a bool,
and change the intermediate contract; each loses the first relation.

The original trace
`runs/current-dataflow-p2-native-gated-20261007-online/online_final_trace.json`
has SHA-256
`f5af69ccf92ee3bae8fa26df3d0a916733e768815169f7449a34cffaabc799e2`
and 24,508 events. Read-only re-audit returned four bounded relations with
retirement event IDs 4,911, 12,192, 17,222, and 22,204; all four still
have `explicit_source_token_on_retirement=false`. The original frozen RTL
run and fresh replay are recorded in
[the native receipt report](current-dataflow-p2-native-irq-sampled-receipt-20261007.md).
This consumer change has no new online RTL run or fresh replay claim.

Verification:

```text
PYTHONPATH=src:. pytest -q tests/scenario/test_pin8_native_trap_relation.py \
  tests/scenario/test_pin8_trap_retirement_certificates.py \
  tests/scenario/test_pin8_cpu_irq_certificates.py \
  tests/local_harness/test_cpu_native_irq_receipt.py \
  tests/local_harness/test_cpu_native_retirement_receipt.py
54 passed, 21 subtests passed in 66.09s
git diff --check: exit 0
python3 -m compileall -q on the changed Python files: exit 0
```

This guard narrows trust in the existing architecture relation. It does not
advance P2 to exact trap identity or complete pin8 to GPIO A propagation.
