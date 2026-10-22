# P7 I5 candidate acceptance record (2026-10-18; supplemented 2026-10-22)

Status: **bounded I5 execution, current-source CLI refusal, and negative-group evidence independently audited; P7-E/P6/P7/P8 remain OPEN**.

Later follow-up: [selected F4 runtime-path admission](compiled-f4-runtime-path-admission-20261022.md) configures the actual session and fresh replay; new Timer/SPI evidence is separate from this frozen I5 run. The 504-source match below was observed at the saved 2026-10-22 13:39:13Z audit checkpoint; subsequent implementation changed source files.

Independent current-source raw-evidence and P7-E rubric review: [Attempt1 audit](P7_I5_ATTEMPT1_INDEPENDENT_AUDIT_20261022.md).

The frozen 2026-10-18 [attempt2 independent terminal audit](P7_I5_ATTEMPT2_INDEPENDENT_AUDIT_20261018.md), commit `c3d65db`, recorded all 20 N1–N8 cases successfully (2/1/1/5/2/1/2/6), zero failure/error/skip; actual CVE2 + PULP timer RFuzz produced 2 certified receipts, full fresh replay matched 536 events / 2 records, and receipt SHA join was independently checked. Controller exit0; source/tools/client and file/directory freezes unchanged. Fresh DUTs have explicit reaped/exit0 receipts; original DUTs were absent at observation, but their independent exit rc receipts were unavailable for that historical run. The current-source 2026-10-22 supplement below has separate explicit original/fresh exit receipts.

## 2026-10-22 current-source supplemental attempt-1

Saved evidence: [`attempt-1`](evidence/p7-i5-cv32e20-pulp-timer-20261022/attempt-1/). This supplements the frozen 2026-10-18 Attempt2 with a current-source CV32E20 + PULP Timer run and explicit original/fresh process return-code receipts.

- The saved CLI invocation used `--executor compiled-f4-rfuzz`, no `--runtime` family fallback, and a 60-second search budget. The run completed with exit 0 and **5/5 certified** receipts for `F4:ram.image`, source `peripheral.TIMER0_CTRL.value.mmio`; the receipt join has five certified rows and status `ok`.
- Full fresh replay matched **1,340 events / 5 records**. First and fresh `compiled_f4_prefix.json` files are byte-identical (SHA-256 `849ae432d6351204c56e500b228dd4e5c1e2d79058d8a259a10b53ce91992328`); the normalized prefix digest is `4a2890ade43a24ec465475cd524554cd7629bfa32ef9d8cec47d1a561eb9a9ec`, and semantic hash is `ead0380aafc4497d5184ca65036b141f3ee6e24b3fd2ce4bfc01f1a09c89e18f`.
- Both original and fresh CPU/peripheral process audits are closed: all four processes were reaped with return code 0. Original PIDs were 364253/364296; fresh PIDs were 369117/369160; each process has a distinct execution nonce. The independent evidence audit also verified the receipt hash join, source-lock/artifact/runtime file identities, and all 17 bundle manifest entries. Separately, a local read-only recheck found all 504 `compiled_f4_prefix.source_files` hashes equal to the working tree at that saved audit checkpoint; machine-readable results are saved in [`source-closure-recheck.json`](evidence/p7-i5-cv32e20-pulp-timer-20261022/attempt-1/invocation/source-closure-recheck.json). The independent reviewer checked 38 execution-identity source entries.
- The saved CV32E40P override invocation was refused before harness generation or session startup: `composition-profile-not-reviewed` at `/cpu/request`, CLI exit 1, session `not_requested`. This is a useful fail-closed configuration-mismatch negative; N1–N8 are separately covered by the software negative-group command.
- The saved software negative-group run exited 0 with **231 passed, 2 skipped**. Its `pytest -q` log does not preserve the skipped test IDs or reasons.

This is a bounded selected-path result, not formal P7-E acceptance. The compiled-F4 prefix records a same-run selected-path binding, but this saved online session reports `runtime_path_status=legacy_unchecked`; only F4 is runtime-supported in the execution projection, while the general D3 runtime-path contract is not shown flowing through the live session. `capability-report.assertion_results` is empty. The generated D2 harness artifacts have `binary=null` / `built=false` and `structural_only` build status, so no D2 harness binary identity is tied to the native F4 execution. The capability report leaves F5 IRQ and F6 DMA unsupported, with `Cross-component accepted=0` and `Bug confirmed=0`.

The P7-D performance fields also remain insufficient for the plan's gate: effective cases/s and certified chains/s are both `0.0`; the all-receipt rate is about `0.064/s`, and build/RTL compile cost is absent. The `kfuzz` client is recorded as `external_binary_only`, so this is not a clean-room rebuild. These limits do not invalidate the saved F4 transaction evidence, but they prevent promoting it to broad same-protocol onboarding or formal P7-E completion. P6's persistent single-harness, per-edge-source, and closed-loop four-hit gaps remain open; P8 S1c remains 1.37x against its 5x target.

## Historical candidate evidence

## Real execution evidence

Commit `ade3fe6` (production source same as `07b207b` plus S4 fixes):

```
PYTHONPATH=src python3 scripts/auto_harness_test.py \
  --cpu configs/cpus/cv32e20/component_profile.json \
  --ip configs/peripherals/pulp_timer/component_profile.json \
  --ip-capability configs/scenarios/compiled-f4-obi-apb-timer-cve2/test_capability.json \
  --compose configs/scenarios/compiled-f4-obi-apb-timer-cve2/compose.json \
  --executor compiled-f4-rfuzz \
  --client-binary runs/rfuzz_client_native_build/target/debug/kfuzz \
  --budget-seconds 60 --max-tests 8 --rounds-per-case 32 \
  --output runs/p7-i4-real-ade3fe6 --cache-dir .superpowers/cache-p7-i4-ade3fe6
```

Result: `status=complete`, client rc 0, 4 tests / 4 certified, receipt join ok,
fresh `matches=true/full`, `Coverage-guided searched=3`, `RTL operational=3`,
`family_fallback=false`. The CPU is CV32E20 (new CPU), the target is the PULP
timer generic APB storage path (new IP); D1–D3 produce `executable=4/6` and
the one F4 target `path_id=F4:ram.image`, source
`peripheral.TIMER0_CTRL.value.mmio`.

This satisfies the "new CPU + new IP auto-run" execution part of I5. It does
**not** by itself satisfy the formal P7 gate: the later frozen-snapshot negative run and audit are recorded above; original DUT exit receipts remain a limitation.

## Negative-fixture mapping (N1–N8 from the P7 design)

| # | Expected refusal | Current test | Result |
|---|---|---|---|
| N1 | similarly named CPU profile cannot borrow loaded artifact | `tests/integration/test_compiled_artifact_admission.py::test_similarly_named_cpu_profile_cannot_borrow_loaded_cpu` | pass |
| N2 | sidecar matched by `component_id`, not filename | `tests/integration/test_auto_harness_test.py::test_an_explicit_capability_sidecar_is_matched_by_component_id` | pass |
| N3 | forced `target.apb3` template on GPIO → `apb3-register-unowned-input` | `tests/onboarding/test_p7_n3_forced_apb3.py`; implemented at `1194b32`, executed in attempt2 | pass (1 case) |
| N4 | wrong register/offset/width/mask/address | `tests/integration/test_compiled_f4_storage_producer.py::test_wrong_register_offset_width_mask_or_address_refused` | pass |
| N5 | wrong artifact kind (AHB/APB) refused before consumption | `tests/integration/test_generated_factory_consumption.py::test_supplied_artifact_kind_and_instance_are_checked_before_consumption` | pass |
| N6 | undeclared endpoint/window refused by name | `tests/local_harness/test_harness_set.py::test_an_undeclared_endpoint_is_refused_by_name` | pass |
| N7 | uncompiled physical source not silently added | `tests/integration/test_compiled_artifact_admission.py::test_uncompiled_physical_source_is_refused_instead_of_silently_added` | pass |
| N8 | family instance/shape mismatch refused | `tests/integration/test_auto_harness_test.py::test_a_composition_that_does_not_satisfy_the_family_is_refused` | pass |

Focused negative run at `ade3fe6`:

```
pytest -q tests/integration/test_compiled_artifact_admission.py \
  tests/integration/test_auto_harness_test.py \
  tests/integration/test_compiled_f4_storage_producer.py
# 137 passed in 122.20s
```

N5/N6 direct check: 3 passed in 20.34s.

## Remaining scope and evidence limits

The dedicated N3 case and all N1–N8 groups have now executed in the independently frozen attempt2, together with the CV32E20+timer RFuzz/full-fresh gate. The original DUTs lack independent exit rc receipts; process absence does not supply those return codes. Fresh DUT reaping and controller termination are explicitly recorded.

The compiled executor evidence supports the declared F4 target. F1 retirement certification, F2/F3 execution mapping, F5 IRQ and F6 DMA require their own acceptance evidence; this audit does not grant them or full P7 completion. P6/P7/P8 remain OPEN.
