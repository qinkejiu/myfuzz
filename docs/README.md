# Docs

Current documentation is intentionally small. Test results should be appended to
`ALL_TEST_RESULTS_MASTER.md`; implementation and artifact locations should be
kept in `PROJECT_SUMMARY_AND_ARTIFACT_INDEX_20260615.md`.

## Kept Files

- `ALL_TEST_RESULTS_MASTER.md`: unified long/short test results table.
- `PROJECT_SUMMARY_AND_ARTIFACT_INDEX_20260615.md`: implementation and artifact index.
- `IBEX_41_PRE_POST_AND_BASELINE_HARNESS_20260616.md`: baseline harness, pre/post variants, and 41-way run summary.
- `IBEX_SCHEME5_BIT_CONSTRAINTS.md`: scheme5 constraint implementation notes.
- `SCHEME5_IDEA_AND_CURRENT_EFFECT.md`: scheme5 as dependency-aware multi-harness fuzzing, including idea and current Ibex semantic-modeling vs baseline preliminary results.
- `XIANGSHAN_XSTOP_AND_SCHEME5_NOTES_20260616.md`: XiangShan `XSTop` hierarchy, scheme5 system/module/multi-component strategy notes, candidate RFUZZ/DirectFuzz/HW-Fuzz/SymbFuzz target classification, and recommended multi-component test cases.
- `MULTICOMPONENT_SCHEME5_TARGETS_AND_CASES_20260617.md`: standalone structured comparison of candidate designs versus `XSTop`, multi-component scheme5 flow, and recommended test cases.
- `CANDIDATE_COMPONENT_PROJECTS_RVX_COREV_PULP_20260617.md`: local clone and suitability notes for RVX, CV32E40P, CORE-V MCU, PULPissimo, and PULP as scheme5 multi-component targets.
- `CPU_IP_MULTICOMPONENT_EXPERIMENT_PLAN.md`: current concrete plan for an Ibex + multiple IP target, including the direct-slice baseline, dependency-aware projection variant, dependency manifest, local/remote directory layout, and first smoke-test milestones.
- `PROTOCOL_CPU_PERIPHERAL_REFERENCE_20260906.md`: protocol contracts, CPU native/integration/bridge boundaries, common peripheral catalog, dependency-aware composition rules, and the fixed RFuzz input ABI.
- `RISCV_ISA_ENCODING_REFERENCE_20260906.md`: RISC-V CPU profiles plus RV32I/RV64I/M/A/F/D/C instruction names, field layouts, 0/1 encoding rules, privileged/CSR boundaries, and optional B/Z extension catalog.
- `research/protocol-research-notes.md`: source-oriented protocol notes used to cross-check the reference contract.
- `research/component-rfuzz-research-notes.md`: source-oriented CPU/component, dependency graph, RFuzz ABI, and long-run metadata notes.
