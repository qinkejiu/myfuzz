# P2 pin8 native CPU IRQ sampling receipt (2026-10-07)

## Implementation and proof boundary

The dual-source Ibex/PULP online factory and CLI now expose an explicit `native_irq_receipts` / `--native-irq-receipts` opt-in that requires RVFI. It enables the existing pinned Ibex `GeneratedCve2Session` native receipt path for this scenario. The CPU session parses the real `STEP_CPU` command receipt: the pre-edge `irq_external_i` value and `irq_taken_pre` controller decision, the post-edge notification, the command sequence and tick, and a session-local `take_key`. The runner records `cpu_external_irq_sample` and `cpu_external_irq_taken`, with the take's `sample_event_id` referring to that same parsed receipt. Saved fresh replay selects the opt-in only from the verified session manifest and checks the exact native IRQ contract. The default run identity and legacy replay selection remain unchanged.

The `take_key` is a **host observation ID assigned after an actual RTL pre-edge decision**, not an RTL-carried source token. It is not copied onto `cpu_retire`. At each observed acceptance, the same command's post-edge RVFI has `valid=0`; the first `intr=1` retirement is five CPU ticks later. Attaching the take key to that later retirement in the CPU session would be a temporal inference, so this implementation does not make that claim. The existing `Pin8TrapRetirementCertificates` relation remains bounded and architectural. No full IRQ→MMIO→RAM→GPIO A identity certificate is issued.

## Frozen real RTL gate

The final source was frozen under `/home/qinkejiu/myfuzz_snapshot_p2_native_gated_20261007`. The 2,753 files under `src/`, `configs/`, `scripts/`, `schemas/`, and `tests/` are recorded in `runs/current-dataflow-p2-native-gated-snapshot-20261007.sha256` (manifest SHA-256 `a69e31e34bdaf237b3aad9c0762ab180629b431d4cfa28cfe3febc5eb4b9cac9`). The snapshot links the pinned third-party RTL from the preceding frozen P4 snapshot. This final snapshot includes the tested fail-closed manifest selector for explicit null and non-object CPU identities. After run and replay, all 2,753 hashes still matched.

```bash
python3 scripts/run_ibex_pulp_online.py run \
  --client-binary third_party/rfuzz/upstream/rfuzz_reference/fuzzer/target/release/kfuzz \
  --cache-dir /home/qinkejiu/myfuzz/runs/current-dataflow-p2-native-gated-cache-20261007 \
  --output /home/qinkejiu/myfuzz/runs/current-dataflow-p2-native-gated-20261007-online \
  --seconds 25 --max-tests 25 --seed 20261007 \
  --run-id current-dataflow-p2-native-gated-20261007 \
  --cpu-retirement --gpio-consumption --native-irq-receipts
```

The run exited 0 with **18/18 complete**, 25.457 effective search seconds and 24,508 events. The full trace is `runs/current-dataflow-p2-native-gated-20261007-online/online_final_trace.json` (SHA-256 `f5af69ccf92ee3bae8fa26df3d0a916733e768815169f7449a34cffaabc799e2`). An independent read-only audit found four existing exact `pin8_admission_to_cpu_irq_taken` certificates. Each has a same-tick parsed native `cpu_external_irq_sample` and `cpu_external_irq_taken` immediately before the runner's `cpu_irq_input` and `cpu_irq_taken` records:

| Pin8 source ID | Native take event / key | Native receipt sequence and CPU tick | Runner take event | First `intr=1` RVFI retirement / tick |
| ---: | --- | ---: | ---: | ---: |
| 1 | 4,699 / `cpu:0:1` | 122 | 4,701 | 4,911 / 127 |
| 3 | 11,984 / `cpu:0:2` | 314 | 11,986 | 12,192 / 319 |
| 5 | 17,014 / `cpu:0:3` | 442 | 17,016 | 17,222 / 447 |
| 6 | 21,996 / `cpu:0:4` | 570 | 21,998 | 22,204 / 575 |

For each native take, the preceding sample's `sample_event_id`, command scope, parsed `receipt_id`, local tick, actual pre-edge IRQ input of one, and `irq_taken_pre=1` agree. The runner's referenced CPU step has the same local tick, `inputs.irq=1`, and `outputs.irq_taken_pre=1`. The native receipt proves a real CPU controller decision on that step; the later RVFI relation remains an architectural association.

The full trace passed fresh replay from an independent cache:

```bash
python3 scripts/run_ibex_pulp_online.py replay \
  --cache-dir /home/qinkejiu/myfuzz/runs/current-dataflow-p2-native-gated-replay-cache-20261007 \
  --plan /home/qinkejiu/myfuzz/runs/current-dataflow-p2-native-gated-20261007-online/online_plan.json \
  --trace /home/qinkejiu/myfuzz/runs/current-dataflow-p2-native-gated-20261007-online/online_final_trace.json
```

Result: `matches=true`, with no first difference.

## Verification

Tests cover the opt-in type and RVFI prerequisites, CLI forwarding, saved verified manifest selection for fresh replay, and the pre/post native receipt fields in the existing CPU session suite. Focused command:

```bash
PYTHONPATH=src:. pytest -q \
  tests/scenario/test_pin8_native_irq_optin.py \
  tests/scenario/test_gpio_profile_selection.py \
  tests/integration/test_retirement_replay_selection_review.py \
  tests/local_harness/test_cpu_native_irq_receipt.py \
  tests/local_harness/test_cpu_native_retirement_receipt.py
```

The native receipt path does not add a take key to RVFI. A future exact CPU acceptance-to-retirement claim needs an authenticated causal state or RTL-carried identity across the five-tick gap; order and PC constraints alone support only the existing bounded relation.

The focused suite completed with **38 passed, 38 subtests passed**. `git diff --check` exited 0.
