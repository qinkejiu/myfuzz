# Opt-in APB storage generation increment

2026-10-17. Implements approved e3790c1 first atomic increment only. No frontend, remote operation, elaboration, DUT compilation, model, native command, session/build/reset/version producer or compiled-F4 admission change.

## Interface and evidence boundary

Optional local_harness.v2 tuning key `apb_storage_observations` is a list of closed `endpoint_id`, `contract_id`, `register` records, unique by endpoint. Omitted selector leaves the tuning document key absent. The existing APB full-word policy accepts exactly its actual target endpoint. Selection rechecks the registered source contract against actual source/profile bytes; renamed GPIO/unknown contract/register/foreign endpoint cannot select timer storage.

The renderer adds ten read-only outputs: value32, normalized reset1, and eight actual ABI-derived APB signals. No driven input, setup read/write, expected value, new clock or reset sequence. Dedicated `storage_probe_ports` and `storage_observation` metadata accompany the `storage_probes` C++ raw group. Conservative reply sizing includes this group. Exact whole-runtime canonical projection includes both metadata fields and refuses rehashed wrong hierarchy/comment/procedural/duplicate metadata. Both code-owned contract modules are explicit generated executor implementation source pins.

The storage expression remains prospective. `hierarchy_verified`, `native_verified`, `reset_authority`, `version_authority`, `source_authority` are false. Source mapping or raw JSON sample validation cannot issue a token or establish measured hardware provenance. Actual generated hierarchy, compilation, reset capture, complete writer/version observation and live source authority remain future gates. This is not F4 new-IP admission or P7 acceptance.

## Pure controls

- Initial intended RED: new selector unsupported and probe consumer module absent; 2 failed, 1 passed (`red.log`). An earlier shell invocation could not find `python`; it is not counted as feature RED.
- Final command: `PYTHONPATH=src python3 -m pytest -q tests/local_harness/test_apb_storage_probe_generation.py tests/local_harness/test_generic_apb_trace_verification.py tests/local_harness/test_generic_apb_identity.py tests/local_harness/test_apb_storage_source_contract.py tests/local_harness/test_ahb_cpu_observer.py`
- Actual final: **168 passed, 5 skipped, 12.23s**, `green-final.log`. Five skips are GPIO instances of timer-only selected mutation controls; separate GPIO selection rejection executes and passes. No skip is claimed as a passed gate.
- Actual saved ABI facts are explicitly software fixtures; Popen fixture guard permits only git source checks and refuses external frontend/compiler/model calls.
- Non-opt-in timer and GPIO wrapper runtime and complete C++ text compare byte-for-byte against pinned pre-increment renderer/driver. Thus reset/READY/tick code in those drivers is identical. Optional schema document key remains absent. Other protocols receive no generated storage branch or group; no actual OBI/AHB native claim made.
- Selected source, wrong-source/unknown selection, duplicates/expressions, measured-dict shape/bool/overflow, canonical rehashed mutation refusal and explicit implementation-source pins covered. Existing source-contract tests retain parameter/reset/decode/register/source-byte negatives.
- Historical APB extraction and AHB inverse-extraction proofs now consume the exact pinned pre-increment renderer, rather than requiring a later feature body to equal its historical body. Current public admission prefix remains compared exactly; current AHB helper AST remains compared exactly. Root explicitly authorized both narrow test updates. No fuzzy normalization or skipped historical test.
- Intermediate fixture assertion typos (`cpp` vs `cpp_text`, executor binding nesting) and expected historical AST failures were corrected; final log is authoritative. `git diff --check` clean.

## Owned scope

New apb_storage_probe_contract module/test; tuning, APB template, runtime renderer, driver renderer, canonical APB verifier; existing `test_generic_apb_trace_verification.py` and `test_ahb_cpu_observer.py` historical assertions. Pre-increment renderer/driver, raw receipts and source freeze are in `.superpowers/apb-storage-probe-generation/`. Existing source-contract module unchanged. Renderer ownership coordinated with cpu_axi_events, which has separate new gate scripts only.
