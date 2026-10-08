# P5 controlled IRQ checker calibration (2026-10-07)

## Invariant and injection boundary

`IbexPulpOnlineChecker` checks that a GPIO B IRQ source started toward the CPU only after an observed GPIO B IRQ output of 1. `ControlledIrqOutputFaultChecker` is an explicit calibration wrapper. It waits for a real `gpio_irq_trigger`, the last GPIO B output observation at the same local tick, and the subsequent `source_start` from `gpio_b.irq` to `cpu.irq`. It copies that one output event in the checker input and forces its existing `irq`/`interrupt` aliases to 0. The wrapper passes all other events unchanged to the default checker. If the selected perturbation does not yield `gpio_b_irq_source_mismatch`, it raises an error instead of claiming a successful calibration. Missing trigger, wrong tick, absent or inconsistent output, and absent source start cause no injection.

The raw Runner journal, saved RTL trace, and DUT state are **not changed**. This calibrates checker sensitivity to one deliberately corrupted observation at the checker delivery boundary. It does not assert an RTL design bug or an actual CPU interrupt fault. The wrapper's static `checker_input_irq_output_zero.v1` configuration and source SHA-256 are recorded in the saved session checker identity. Its finding metadata retains the observed case, original event ID, source-start event ID, GPIO local tick, same-case source admissions, and the source-start provenance status. The latter is `unknown` with no origin admission IDs in this run, so the finding is not attributed to a complete source-to-CPU causal chain.

## Tests and saved real RTL run

Test-first `tests/scenario/test_p5_controlled_irq_fault.py` initially failed with `ModuleNotFoundError`; after implementation, **3 passed**. The tests cover the exact contradiction, immutable raw event, missing-trigger refusal, and stable checker identity. A read-only control of the existing 25-case, 31,651-event real trace `runs/current-dataflow-p4-xori-certified-20261007-online/online_final_trace.json` yielded no default-checker findings; perturbing its checker input yielded exactly `gpio_b_irq_source_mismatch` at event 6437 before source-start event 6438.

The live calibration used isolated source `/home/qinkejiu/myfuzz_snapshot_p5_irq_fault_20261007`, with 1,812-file manifest `runs/current-dataflow-p5-irq-fault-snapshot-20261007.sha256` (manifest SHA-256 `ab36f61147a2e65ab21ecd6f4a0da57505d3ab172aa14a05b30460bfe081e2f4`; verification: zero mismatches). It used real Ibex + dual PULP GPIO RTL with authenticated CPU retirement and GPIO consumption probes, seed `20261007`, 45-second cap and 8-test maximum. Output: `runs/current-dataflow-p5-controlled-irq-fault-20261007-online`. It stopped on the calibrated finding after **5 tests: 4 complete, 1 `dut_violation`**. The saved trace has 7,647 raw events. The unfaulted default checker on that entire saved trace reports `()`.
The fifth `receipts.jsonl` entry and saved `failures/online_dut_violation_58da5fbb_1_3_f13d49307cfb514a.json` both record `gpio_b_irq_source_mismatch`; the latter keeps the complete raw trace and replay entrypoint.

| Evidence | Value |
| --- | --- |
| Original GPIO B observation | event 6437, `local_tick_sample`, local tick 195, `interrupt=1` |
| Source-start witness | event 6438, `gpio_b.irq → cpu.irq`, source tick 195 |
| Injected checker input | same event 6437, `interrupt=0` |
| Finding | `gpio_b_irq_source_mismatch` |
| Same-case admissions | `1d64ff237a957cfa7516220c0c689ef4e79331162bea3bf06882981ac3e41281`, `a4885767611a6e95b1a84588aecb4f351bd8fedd6e5a30d39dc7adeb2202a21b` |
| Source-start origin | `unknown`, empty `origin_admission_ids` |
| Raw saved trace SHA-256 | `c6d542d117fdc8275878fb4caacbea9dc996964d11f6a8e2362924380f8d4d2f` |
| Saved plan SHA-256 | `40032057a8e6928ac7c3d8df7ffb32a78912b17b4c9c97368fd40b69bae70194` |
| Fault checker source SHA-256 | `89949efc8b2e2764f85dec2b3b138ece4ddb5a7fcfa41785b616cc040098c0f5` |

## Fresh-process replay

From the same frozen source, a new process verified the saved online run identity, read authenticated CPU/GPIO profile flags (`true`, `true`), constructed a fresh `ControlledIrqOutputFaultChecker`, and confirmed its identity exactly equals the saved manifest checker identity. `replay_online_session` reran fresh RTL with a separate replay cache and that checker. It returned `matches=true`, `first_difference=null`, `difference_context=null`, and `actual_trace.status=finding`, equal to the saved status. Independently inspecting the fresh checker result gave exactly `('gpio_b_irq_source_mismatch',)`, with the same case ID, event IDs 6437/6438, tick 195, perturbation values and source context. Replay itself compares the complete raw trace, status, manifest, schedule and admissions; exact finding-ID equality was checked separately because `ReplayComparison` does not expose finding IDs.

This is a narrow controlled fault-detection and reproduction gate. Full P5 still needs a sourced complete IRQ→CPU→output chain certificate, natural findings if any, longer-run quality comparisons and full 600-second performance acceptance under one frozen identity.
