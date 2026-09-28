# Task 2 report: checker manifest and feedback ABI

Commit: `f7faaa6 feat: add SoC checker feedback ABI`.

## Scope delivered

- Added `configs/soc/checkers/ibex_pulp_gpio_spi.json` with exactly 50 stable bit/ID records, bits 0–49. Every record is `not_assessed` with `monitor-not-implemented`; implemented RTL assertions remain **0**.
- Added immutable `CheckerProperty`/`CheckerProfile` and strict loader. It validates schema, request/target identity, bus widths, ordered contiguous bits, duplicate IDs, known owners/basis kinds, active binding/evidence, and stable reasons. Hashes use canonical JSON bytes and SHA-256.
- The generated Ibex/PULP top exports `checker_eval_o[49:0]` and `checker_fail_o[49:0]`. Both are fixed at zero during this bootstrap. The profile hash appears in the rendered top and in the build/cache identity, so changing a property ID changes artifact identity.
- The profile runtime includes both checker output vectors as observations. The RFuzz profile build appends the 100 checker output bits after the instrumented RTL branch counters and records separate branch and checker ranges, property statuses, profile hash, campaign arm, and an empty required-evaluated subset. The manifest is staged as `checker_profile.json` in the compiled artifact.
- Extended independent structure audit expectation for this specific target to accept exactly two additional 50-bit outputs. A wrong width or an undeclared third output still fails the top-port audit.

## TDD and verification

- Observed initial `ModuleNotFoundError` for the missing loader.
- Observed renderer test failure before adding the checker outputs.
- Observed audit failure for the new ports before extending the audit contract.
- Observed the changed-property-ID artifact-identity test fail before accepting the checker profile argument in rendering.
- Final command: `PYTHONPATH=src:. python3 -m unittest tests.composition.test_soc_checker_profile tests.integration.test_soc_ibex_pulp_dual_profile tests.composition.test_soc_structure_audit -v` — **46 tests passed**.
- `git diff --check` passed.

## Review notes

- This task reserves and reports checker feedback only. No OBI/APB/fabric, GPIO, SPI, or RVFI checker RTL exists yet. A profile record cannot become active in this renderer until a later task adds a real monitor binding; the renderer rejects an active record today.
- The real Verilator/RFuzz profile campaign was not built or run in this task. The focused tests cover manifest validation, output rendering, observation mapping, structural audit, and artifact-identity change.
- Branch counter identities remain in `branch_coverage_ports` and `coverage_instrumentation`; checker event identities remain in `checker_feedback`. The RFuzz counter vector carries both in that order. All checker event counters are zero at this stage and make no pass/fail claim.
