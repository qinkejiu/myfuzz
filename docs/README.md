# 项目文档入口

## 从这里开始

- [工作区目录归类与清理记录](WORKSPACE_INVENTORY.md)：每个顶层目录的性质（当前主线／钉住依赖／证据／历史归档）、本轮清理删了什么与重建了什么、断链声明。
- [系统说明](SYSTEM_OVERVIEW.md)：**现有系统的分层结构、一次运行怎么走、验证体系与已知边界**（想先搞清"这套系统长什么样"从这里读）。
- [组件清单与功能](COMPONENT_REFERENCE.md)：**现有系统各个组件及其功能**（340 个模块按六层分组，逐项职责与证据位置）。
- [吞吐量是多少（实测）](THROUGHPUT.md)：三个口径的每秒例数、分项拆解、与 2026-10-06 同配置运行的 24× 对照、单命令成本探针与改进路径。
- [时钟约束是怎么得到的](CLOCK_CONSTRAINTS.md)：profile 声明 → 请求 tick 数 → 规划期校验编译 → driver 生成 → 宿主核对边沿，逐步取证。
- [四个问题的实证回答](FOUR_QUESTIONS_EVIDENCE.md)：外设事件说明的现状、代码量构成、吞吐瓶颈实测与改进路径、时序处理。
- [按 testcase 讲：运行手册](TESTCASE_RUNBOOK.md)：**以一次 testcase 为单位**讲数据流动、涉及部件、怎么运行（含命令数、耗时构成、重放路径）。
- [testcase 的种类与数据流](TESTCASE_TYPES.md)：**testcase 有哪几种、各自数据怎么流**（T1～T8，含真实分布、闭环判据与边界）。
- [输入的变异依据](INPUT_MUTATION_BASIS.md)：**输入怎么被变异、依据是什么、不允许依据什么**（raw 布局、六道约束闸门、37 拒绝码、反馈权重公式与真实序列）。
- [testcase 与数据流](TESTCASE_AND_DATAFLOW.md)：**一次 testcase 是什么、内部数据怎么流、经过哪些组件**（带真实事件号的两个完整例子）。
- [当前工作进度](CURRENT_PROGRESS.md)：已完成范围、正在验证的工作和下一步；最新状态以此页为准。
- [第一步 P1–P5 复现手册](reproduction/first-step-p1-p5-20261008.md)：按阶段找验收报告、保存运行、可顺序执行的只读命令与本次复核结果。
- [第一步代码与文档核对](reproduction/first-step-code-doc-audit-20261008.md)：按职责归类当前代码、共享依赖、历史路线和冻结证据，并记录核对发现。
- [第一步代码与文档归档](reproduction/first-step-archive-20261008.md)：当前文件快照、分包清单、哈希校验和恢复入口。
- [当前设计](CURRENT_DESIGN.md)：目标和实现边界。
- [计划索引](superpowers/plans/README.md)：总计划、专题任务与历史路线。
- [报告与证据索引](reports/README.md)：按验收范围查报告，再进入原始记录与 replay 材料。
- [快速开始](../QUICKSTART.md)：运行入口；[代码组织](CODE_ORGANIZATION.md)：实现入口。

`docs/` 保存面向使用与交接的说明，`docs/superpowers/plans/` 保存计划，`docs/reports/` 保存验收结论。原始运行证据在 `runs/`，当前工作日志与独立审查在 `.superpowers/sdd/`；日志或计划中的待办不等于已通过验收。

## 当前方案

项目当前主线是在多个独立 CPU/IP harness 中测试真实 RTL。目标是总控环境初始化一次后连续接纳多条 testcase，并让 RTL、RAM 和 pending event 跨例保持；Fuzzer 先选原始 Word 文档中的数据流目标，再按 ISA/协议/组件字段约束变异当前可控的上游源。testcase 是一次指令或外部事件输入及其观察，数据流目标不是 case 边界，真实 RTL 的传播可以跨例继续。现有受限 Ibex＋GPIO/UART 在线 RFuzz 已复用同一 Runner 接纳多例，并保存完整前缀 fresh replay；早期 batch 将多个 source 事件记作一例的入口仍保留。完整逐边来源、通用单指令动作编译及任意组件路径自动绑定仍在实施计划中。

- [当前设计与实现边界](CURRENT_DESIGN.md)：目标架构、输入约束、运行闭环和已知差距。
- [快速开始](../QUICKSTART.md)：生成一个独立 IP harness、记录并重放连续 CPU/GPIO 场景。
- [真实 CPU/IP Harness 运行状态](LOCAL_HARNESS_RUNTIME.md)：已有 profile、协议适配、组合验收和运行限制。
- [当前实施计划](superpowers/plans/2026-10-06-current-dataflow-fuzz-implementation-plan.md)：最终功能、原始 Word 的六类数据流、各阶段已实现内容与验收缺口。
- [代码组织与入口](CODE_ORGANIZATION.md)：当前执行链、共享 helper、历史代码和 CLI 偏差。
- [持续多组件 Fuzz 设计](superpowers/specs/2026-09-27-persistent-multicomponent-fuzz-design.md)：Dependency Path、Fuzzable Source / Bound Input、状态保持和覆盖反馈。
- [独立 Harness 扩展设计](superpowers/specs/2026-10-04-generated-local-harness-five-protocol-design.md)：源码事实、协议模板与声明式微调。
- [阶段验收记录](reports/persistent-scenario-acceptance-20260927.md)：固定场景、状态持久化、依赖和重放证据及限制。
- [P2 受控 UART 入口与退休读取](reports/current-dataflow-p2-controlled-entry-read-20261006.md)：冻结源码的 2048 门禁证明 taken／受控 entry／retired read 各4条、0 barrier，48,315事件完整 fresh 一致；旧256失败保留，后续 Runner 已变，不代表当前源码重验。
- [P2 UART 原生 IRQ taken](reports/current-dataflow-p2-uart-native-irq-20261006.md)：实际队列原因、绑定、CPU 输入与 external taken；完整新进程 wire replay 相等，受控 ISR／操作数来源仍待闭合。
- [P2 UART FIFO 消费验收](reports/current-dataflow-p2-uart-fifo-consumption-20261006.md)：实际 RX 来源、FIFO 留存及完整路由读取身份；738 项软件、2 项真实 RTL、4 例在线与完整 replay 通过。
- [P2 GPIO 消费验收](reports/current-dataflow-p2-gpio-consumption-20261006.md)：固定 GPIO 寄存器、实际 Binding 输入、同步器、原生 IRQ 与读取资源的定向证据；CPU 操作数来源仍未知。
- [当前报告索引](reports/README.md)：按持续场景、生成 harness、CPU/IP 闭环检索证据。
- [计划索引](superpowers/plans/README.md)：当前总计划、专题计划与历史路线。
- [当前仓库整理计划](superpowers/plans/2026-10-06-current-design-repository-cleanup.md)：文件分类和可恢复清理规则。
- [仓库引用审计](reports/current-design-cleanup-source-audit-20261006.md)：本轮移出文件、保留依赖和静态检查结果。

## 代码导航

| 目录 | 当前职责 |
|---|---|
| `src/myfuzz/scenario/` | Genome、依赖图、Runner、Router、Scheduler、持久状态、checker、coverage 和 replay |
| `src/myfuzz/local_harness/` | 从已验证组件 profile 建立独立 CPU/IP harness 与本地协议 session |
| `src/myfuzz/integration/scenario_*` | RFuzz 候选、campaign、反馈传输与场景 replay 接入 |
| `src/myfuzz/protocols/` | 协议描述、适配与可复用 RTL peer/checker |
| `configs/cpus/`、`configs/peripherals/` | CPU/IP 源码事实、profile、协议和 harness 微调 |
| `tests/scenario/`、`tests/local_harness/`、`tests/integration/` | 依赖、协议、真实 RTL 场景与 replay 验收 |
| `third_party/` | 固定版本的真实 CPU/IP RTL 和依赖，构建/重放需要时保留 |
| `runs/scenario/acceptance/` | 固定场景证据与 replay 材料；不要当作缓存批量删除 |

## 单独的历史路线

仓库还保留更早的完整 SoC 生成/总线组合、直接组件 fuzz、方案对照和插桩实验。它们用于历史对照或仍被共享工具依赖时继续保留，不代表当前主方案，也不应作为独立 Harness 自动数据流能力的验收证据。

- [2026-09-14 SoC 组合目标](PROJECT_GOALS.md)：历史规格；当时要求生成具体 SoC 总线和互连。
- `docs/superpowers/plans/2026-09-*soc*`、`docs/reports/soc-*`：历史计划和验收报告，结论只适用于各自标注的源码身份。
- [统一历史测试索引](ALL_TEST_RESULTS_MASTER.md)：按日期和实现路线检索旧结果。

清理代码前必须检查 imports、配置、CLI、测试及 replay factory。`composition/` 中有独立 Harness 当前共用的源码事实、profile 和端口分析模块；不能仅凭目录名或 `soc_` 前缀删除。
