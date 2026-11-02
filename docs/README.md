# 文档导航

先看[当前进度](CURRENT_PROGRESS.md)确认状态，再按用途选择文档。历史报告中的通过结论只适用于其记录的源码和证据。

## 入门与日常使用

| 目的 | 文档 |
|---|---|
| 找目录、代码和命令 | [工作区地图](WORKSPACE_MAP.md)、[代码组织](CODE_ORGANIZATION.md) |
| 跑第一个示例 | [快速开始](../QUICKSTART.md) |
| 理解总体结构 | [系统说明](SYSTEM_OVERVIEW.md)、[当前设计](CURRENT_DESIGN.md) |
| 理解组件与支持范围 | [组件参考](COMPONENT_REFERENCE.md)、[运行能力](LOCAL_HARNESS_RUNTIME.md) |
| 按 testcase 运行 | [运行手册](TESTCASE_RUNBOOK.md)、[类型](TESTCASE_TYPES.md)、[数据流示例](TESTCASE_AND_DATAFLOW.md) |
| 理解变异、时钟与性能 | [变异依据](INPUT_MUTATION_BASIS.md)、[时钟约束](CLOCK_CONSTRAINTS.md)、[吞吐测量](THROUGHPUT.md)、[实证问答](FOUR_QUESTIONS_EVIDENCE.md) |

## 通用化框架与 DS 执行

[当前系统能力盘点（2026-11-01）](current-system-capabilities-20261101.md) 汇总最新单进程入口、真实验证范围、限制和性能口径。

2026-11-02 的 P1 增量（混合协议多目标、IRQ 任意拓扑、DMA 路由到四种目标协议、每模型时钟、profile/行为表达力、三个替换样本）见[P1 验收报告](reports/p1-acceptance-final-20261102.md)；逐个 CPU profile 的退休/trap/IRQ/时序形态见[CPU 能力矩阵](cpu-capability-matrix.md)。

[通用系统分阶段路线](universal-system-roadmap.md)记录当前 F1–F4、IRQ/DMA、RISC-V 指令和性能优化的顺序与验收条件。

统一入口的闭环变异、F1 短程序、前缀重放和设备行为声明见[闭环使用说明](inprocess-fuzz-loop.md)与[行为声明](inprocess-behavior-declarations.md)；误报修正/失败分类见[修正证据](../runs/stage2-task1-fix-20261101/README.md)，长跑内存见[长跑报告](reports/fuzz-longrun-20261101.md)，新 IP 接入见[I2C 接入](reports/new-ip-onboarding-20261101.md)，合并验收见[批量验收](../runs/stage2-acceptance-20261101/README.md)，早期分项计时见[性能报告](reports/fuzz-loop-performance-20261101.md)。

[架构规格](superpowers/specs/2026-10-26-generic-runtime-framework-design.md)定义能力、协议、语义和证据边界；[执行计划](superpowers/plans/2026-10-26-generic-runtime-ds-implementation-plan.md)按 G0–G10 分期。[独立组件数据流运行说明](independent-dataflow-runtime.md)介绍已有的混合路径入口和覆盖率采集，以及当前尚未完成的部分。

## 开发与验收

- [当前总实施计划](superpowers/plans/2026-10-06-current-dataflow-fuzz-implementation-plan.md)：目标和验收门。
- [P6 逐协议清单](superpowers/plans/2026-10-13-p6-per-protocol-row-checklist.md)、[P7 自动接入计划](superpowers/plans/2026-10-13-p7-automatic-onboarding-implementation.md)。
- [全部计划索引](superpowers/plans/README.md)、[设计规格目录](superpowers/specs/)。
- [报告与证据索引](reports/README.md)：从结论进入原始证据。
- [复现入口](reproduction/README.md)：复现、备份、归档和发布。
- [脚本导航](../scripts/README.md)、[配置导航](../configs/README.md)、[测试导航](../tests/README.md)。

## 历史与专题资料

- [第一步 P1–P5 复现](reproduction/first-step-p1-p5-20261008.md)、[代码文档核对](reproduction/first-step-code-doc-audit-20261008.md)、[归档与恢复](reproduction/first-step-archive-20261008.md)。
- [持续多组件设计](superpowers/specs/2026-09-27-persistent-multicomponent-fuzz-design.md)、[独立 harness 设计](superpowers/specs/2026-10-04-generated-local-harness-five-protocol-design.md)。
- [历史 SoC 项目目标](PROJECT_GOALS.md)、[历史测试总索引](history/experiments/ALL_TEST_RESULTS_MASTER.md)。完整 SoC 生成路线与当前独立 harness 路线分别解释。
- [分类历史资料](history/README.md)、[技术参考](reference/README.md)、[研究资料](research/)、[交接资料](handover/)、[图像素材](assets/)。
- [仓库整理台账](REPOSITORY_ORGANIZATION.md)、[历史清理与恢复记录](WORKSPACE_INVENTORY.md)。

文档分类和新增文件放置规则见[工作区地图](WORKSPACE_MAP.md)。`CURRENT_PROGRESS.md` 是状态入口，报告是证据入口，计划是验收依据；三者各司其职。
