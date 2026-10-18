# P7 I5 candidate acceptance record (2026-10-18)

Status: **bounded I5 execution and negative-group evidence independently audited; P6/P7/P8 remain OPEN**.

Latest [attempt2 independent terminal audit](P7_I5_ATTEMPT2_INDEPENDENT_AUDIT_20261018.md), commit `c3d65db`: all 20 N1–N8 cases executed successfully (2/1/1/5/2/1/2/6), zero failure/error/skip; actual CVE2 + PULP timer RFuzz produced 2 certified receipts, full fresh replay matched 536 events / 2 records, and receipt SHA join was independently checked. Controller exit0; source/tools/client and file/directory freezes unchanged. Fresh DUTs have explicit reaped/exit0 receipts; original DUTs were absent at observation, but their independent exit rc receipts remain unavailable.

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
