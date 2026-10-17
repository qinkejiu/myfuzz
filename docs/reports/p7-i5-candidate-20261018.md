# P7 I5 candidate acceptance record (2026-10-18)

Status: **sub-set evidence, not a full P7 declaration**. The new-CPU/IP
execution gate is real; the negative group is mapped to existing tests and one
case (N3) still lacks a dedicated current-source unit test.

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
**not** by itself satisfy the formal P7 gate: the negative group and an
independent snapshot re-run are still required.

## Negative-fixture mapping (N1–N8 from the P7 design)

| # | Expected refusal | Current test | Result |
|---|---|---|---|
| N1 | similarly named CPU profile cannot borrow loaded artifact | `tests/integration/test_compiled_artifact_admission.py::test_similarly_named_cpu_profile_cannot_borrow_loaded_cpu` | pass |
| N2 | sidecar matched by `component_id`, not filename | `tests/integration/test_auto_harness_test.py::test_an_explicit_capability_sidecar_is_matched_by_component_id` | pass |
| N3 | forced `target.apb3` template on GPIO → `apb3-register-unowned-input` | no dedicated current-source test; previously reproduced on the real GPIO path | **open** |
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

## What remains for a full P7 formal gate

1. Add the N3 dedicated generic-path test (GPIO forced APB3 register template →
   named refusal, no harness emitted) and include it in the negative group.
2. Independently re-run the CV32E20+timer gate from a frozen snapshot and
   verify every certificate/prefix field; this repository-session run is not an
   independent audit.
3. State the remaining unsupported paths: F1 retirement certification, F2/F3
   execution mapping, F5 IRQ, F6 DMA; the compiled executor supports only the
   declared F4 target.
4. Do not call P7 complete: the negative group is mostly mapped, not fully
   rebuilt, and the independent audit is outstanding.
