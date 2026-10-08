# P2 pin8 CPU trap retirement architectural relation (2026-10-07)

## Result and boundary

The frozen-source 25-case trace used by the [pin8 CPU IRQ identity report](current-dataflow-p2-pin8-cpu-irq-identity-20261007.md) contains five exact `pin8_admission_to_cpu_irq_taken` certificates. A new independent consumer, `Pin8TrapRetirementCertificates`, relates each accepted IRQ to the first later observed RVFI retirement only under these checks:

- The accepted CPU step exposes a nonnegative RVFI order.
- Exactly one CPU IRQ acceptance is pending; reset, flush, a second acceptance, the first incompatible retirement, or the 1,024-event gap limit cancels it.
- The first retirement has the next RVFI order, `valid=1`, `intr=1`, `trap=0`, and `pc_wdata=0x10200`, the fixed handler entry for this online image.
- The retirement's `producer_event_id` names an actual CPU step with matching `rvfi_valid`, `rvfi_intr`, `rvfi_order`, and `rvfi_pc_wdata`; the recorded physical RVFI sample also agrees.

The consumer emits five `single_pending_irq_architectural_trap_relation` records. This is a bounded **architectural association**, not an exact hardware source token. The `intr=1` retirement is the vector `jal` at `0x1012c`, whose next PC is `0x10200`; the first ISR instruction retires one order later. RVFI retirement itself has no `source_event_id`, GPIO trigger ID, or native `take_key`. The output includes `explicit_source_token_on_retirement=false` and does not extend the exact source identity certificate. It is not a complete IRQ→MMIO→RAM→GPIO A chain and must not count toward P5 full-chain/s.

| Exact CPU IRQ taken | Source event ID | First trap retirement | Acceptance→retirement RVFI order |
| ---: | ---: | ---: | ---: |
| 6,525 | 1 | 6,726 | 35→36 |
| 13,621 | 3 | 13,818 | 72→73 |
| 20,658 | 5 | 20,855 | 106→107 |
| 25,461 | 6 | 25,658 | 134→135 |
| 28,066 | 7 | 28,264 | 158→159 |

## Downstream identity gap

After each of these trap retirements the saved real RTL trace contains a GPIO B PADIN MMIO read, an accepted retired `lw`, a host RAM write at `0x10000`, and a GPIO A `out` register commit. For the first sequence, GPIO B MMIO delivery event 7,360 has full CPU data transaction sequence 11; `cpu_retirement_match` event 7,415 accepts that same transaction and retired `lw` order 42. Host RAM write event 7,494 has data transaction sequence 12; match event 7,575 accepts the corresponding retired `sw` order 44. These transaction identities support local MMIO/RAM joins, but neither the transactions, retirement records, nor GPIO A commit carries the accepted IRQ `source_event_id` or trigger ID. Their occurrence after the trap is insufficient for an exact source-to-output claim.

All five observed ISR runs cross an online case boundary before the GPIO A output instruction retires: IRQ/trap case indices 4, 10, 16, 20, and 22 correspond to output retirement case indices 5, 11, 17, 21, and 23. `observed_case` therefore cannot serve as an ISR or source identity. Any next-stage relation must use continuous CPU reset epoch, RVFI order and PC sequence, the reviewed ISR image, and exact CPU data transaction identities. It must reject a second IRQ, reset, flush, unexpected retirement, changed instruction image, or incomplete transaction. Even those checks would establish a bounded **architectural ISR execution relation**; source-exact propagation additionally requires authenticated IRQ-to-ISR context and operand/register-version joins through the PADIN load, RAM store, shift, and GPIO A store.

The missing producer is a source-bearing CPU ISR context or an equivalent architectural lineage record from IRQ acceptance to the retirement and its instruction/data transaction stream. Such a record must distinguish multiple IRQ acceptances and interrupted control flow; copying the last seen IRQ ID onto later events would be unsound. It also needs explicit RVFI register-version joins through `lw`, `sw`, shift, and GPIO A output commit to prove data propagation, not just handler execution.

## Verification

The source trace is `runs/current-dataflow-p2-pin8-cpu-irq-identity-snapshot-20261007-online/online_final_trace.json` (SHA-256 `6bb05b8e3e718c6b7f16a46943fb27014f36b5f7ec85e078149b135a62927694`). Its original online run and full fresh replay are documented in the linked report. This follow-up is a read-only analysis of those saved RTL events, not a new RTL run. Tests use the unmodified real trace and then mutate order, `intr`, entry PC, producer step ID, physical observation, competing acceptance, reset, first retirement, and event-gap bound; each damaged first relation is rejected.

```bash
PYTHONPATH=src:. python3 -m pytest -q \
  tests/scenario/test_pin8_trap_retirement_certificates.py \
  tests/scenario/test_pin8_cpu_irq_certificates.py \
  tests/scenario/test_pin8_irq_certificates.py
```

Result: **14 passed**. `git diff --check` and Python `compileall` also exited 0.
