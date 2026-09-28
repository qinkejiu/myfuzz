# Docs

## 持续多组件 Fuzz 当前方向（2026-09-27）

新方案让 Ibex/CVA6 与 OpenTitan GPIO 等真实 RTL 在各自 harness 中持续运行，跨组件只传递真实观察到的数据和事件，不自动构造具体 SoC 总线。输入由 Fuzzable Source / Bound Input 所有权约束；同一 testcase 内保持内存、事务和局部 RTL 状态。

- [目标设计](superpowers/specs/2026-09-27-persistent-multicomponent-fuzz-design.md)
- [实施与验收计划](superpowers/plans/2026-09-27-persistent-multicomponent-fuzz-implementation.md)
- [阶段验收记录](reports/persistent-scenario-acceptance-20260927.md)

本地已保存两方向、每方向两份固定 Genome 的真实 Ibex＋双 OpenTitan GPIO 两轮闭环包。CPU 源为 `case-ibex-two-gpio-closed-two-rounds-v4` 与 `case-ibex-two-gpio-closed-two-rounds-variant-v4`；外部 GPIO 源为 `case-external-gpio-closed-two-rounds-v2` 与 `case-external-gpio-closed-two-rounds-variant-v2`，均位于 `runs/scenario/acceptance/`。四份包各自经过事件级闭环检查、资源预算检查和全新进程重放，末态 IRQ 为低电平且没有待响应。重放 CPU 源包：

另有对应的四份 `*-1024ticks-v1` 扩展包，每份 CPU 在两轮真实闭环之后继续运行至 1,040 个局部周期，并独立重放匹配。`case-external-gpio-persistent-accumulation-v2` 记录了同一真实 Ibex testcase 中 RAM S=5→8→17 的持续演化；`case-rep01-combined-ibex-two-gpio-v1` 在同一真实 testcase 中组合首次未知读、部分写、延迟响应、双轮 IRQ 和 warm/cold reset。七份短闭环/切边对照包、四份长包、累加包和 REP-01 包合计 13 份当前源码身份的证据，具体门禁状态见阶段验收记录。

```bash
PYTHONPATH=src:. python3 scripts/replay_scenario.py \
  --evidence runs/scenario/acceptance/case-ibex-two-gpio-closed-two-rounds-v4 \
  --factory myfuzz.scenario.examples:make_ibex_two_gpio_runner \
  --rebuild --compare-trace
```

该包和当前局部回归不等于 G0～G4 全部通过；剩余门禁见阶段验收记录。以下早期 SoC 组合文档保留为历史资料，不作为本方案的完成状态。

## 当前入口（2026-09-25）

- [项目目标](PROJECT_GOALS.md)：SoC 自动组合、输入约束和组件内部缺陷归因的研究目标。
- [后续实施路线图](superpowers/plans/2026-09-22-soc-next-steps-roadmap.md)：阶段状态、验收边界和仍未完成的任务。
- [能力矩阵](reports/soc-capability-matrix-20260921.md)：当前支持、拒绝和未评估的协议/机制。
- [设计验收报告](reports/soc-design-acceptance-20260921.md)：SoC 组合、RFuzz 输入、中断和归因的验收证据与限制。
- [最新插装审计](reports/verilog-instrumenter-audit-20260925.md)：Verilog 分支插装的实现、修复、验证和未覆盖语法边界。
- [插装修复计划](superpowers/plans/2026-09-25-verilog-instrumenter-repairs.md)：本轮插装问题修复及待验收项。
- [中断与输入连接说明](superpowers/specs/2026-09-22-soc-top-interrupt-input-wiring-design.md)：SoC 顶层中断路径及测试输入的数据流。
- [整理台账](REPOSITORY_ORGANIZATION.md)：目录归档、保留原则和可恢复清理记录。

旧验收文档和实施计划保留作历史证据；其状态与结论只适用于文档标注日期，
不得替代以上最新能力矩阵、验收报告和插装审计。新测试结果继续追加
`ALL_TEST_RESULTS_MASTER.md`。

## 历史实现、实验与参考资料

- `ALL_TEST_RESULTS_MASTER.md`: unified long/short test results table.
- `PROJECT_SUMMARY_AND_ARTIFACT_INDEX_20260615.md`: implementation and artifact index.
- `IBEX_41_PRE_POST_AND_BASELINE_HARNESS_20260616.md`: baseline harness, pre/post variants, and 41-way run summary.
- `IBEX_SCHEME5_BIT_CONSTRAINTS.md`: scheme5 constraint implementation notes.
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
