# Docs

## 当前入口（2026-09-14）

- [项目目标](PROJECT_GOALS.md)：两层架构、输入约束、两 CPU × 三系列与混合协议验收。
- [实施计划](superpowers/plans/2026-09-14-soc-composition-and-fuzz.md)：P0–P16 的文件、接口、步骤与门槛。
- [整理台账](REPOSITORY_ORGANIZATION.md)：实际工作区、代码职责、历史文件和可恢复清理。

新测试结果继续追加 `ALL_TEST_RESULTS_MASTER.md`。下列文档保留为历史参考，
其中的当前状态、完成比例、运行门槛以对应日期为限；新目标状态以以上入口为准。

## 历史实现、实验与参考资料

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
- `reports/ibex_protocol_campaign_validation_20260906.md`: complete MVP regression, dependency preflight, low-resource 60-second soak, and evidence audit.
- `research/protocol-research-notes.md`: source-oriented protocol notes used to cross-check the reference contract.
- `research/component-rfuzz-research-notes.md`: source-oriented CPU/component, dependency graph, RFuzz ABI, and long-run metadata notes.
- `generic-composition-usage.md`: source-annotated generic composition smoke, synthetic five-peripheral fixture, fail-closed cases, and the low-resource policy boundary.
- `系统总览与RFuzz约束组合示例_20260909.md`: current Chinese system overview, protocol layers, automatic composition flow, RFuzz constraint semantics, and a complete Ibex RV32IMC input-to-top example.

## 历史 Task8 boundary（不代表最新验收状态）

The generic smoke validates source analysis, capability matching, generated IR,
top-level HDL, source list, and input layout. Its low-resource fields are
returned policy metadata; this smoke does not itself enforce process RSS or
timeouts and is not RTL simulation or an RFuzz campaign. Native APB/AXI/
Wishbone/OBI routing and the real 3x300-second campaign remain separate work.
