# 实施计划索引

## 当前唯一总计划

[当前数据流 Fuzz 实施计划](2026-10-06-current-dataflow-fuzz-implementation-plan.md)分为“最终目标功能”和“逐阶段实现情况”两部分，并逐项覆盖原始 Word 文档的取指、数据读、数据写、MMIO、中断和 DMA 六类流。需求口径以 [当前设计](../../CURRENT_DESIGN.md) 为准；具体组合的实际能力以 [运行能力表](../../LOCAL_HARNESS_RUNTIME.md) 与 [报告索引](../../reports/README.md) 为准。

## 仍适用的专题契约

- [P6 逐协议行适配清单](2026-10-13-p6-per-protocol-row-checklist.md)：把 P6 五行验收句落成逐行可执行清单，含**实测**的模板契约口径（**12 个**：新增从机侧 `target.axi4-lite`）、每个 CPU profile 声明的协议端点、可规划的目标端 profile 清单，以及逐行的"已有什么/缺什么"。结论：行 1/2/4 主要是"接线已有能力"，**行 3（AXI4-Lite）是最短路径**（CPU 与 IP 两侧均可规划、IP 已有独立证据），**行 5（Pico 原生 Ready/Valid）缺口最大**（需新增 MMIO 目标与路由）。**行 3（AXI4-Lite）已闭合**（通用事件层第四种协议、通用寄存器观测 kind、声明式 8N1 peer、多例持久会话与受控错误负例，均有真实 RTL 证据），行 1/2/4/5 仍开放；另新增 **§1.4 CPU 适配目标与协议对应（权威口径，六核）**。

- [P7 已支持协议范围内自动接入与自动测试实现文档](2026-10-13-p7-automatic-onboarding-implementation.md)：把 P7 验收句拆成 D1–D4 可判定交付与 A–E 五阶段路线（声明核对器 → 组合级生成 → 路径/输入编译 → 自动跑通与分级报告 → 端到端验收），含真实入口清单、目标产物、逐阶段验证命令、六项实测陷阱与边界。**P7-B（组合级 harness 生成，D2）已实现**（`local_harness/harness_set.py` ＋ `scripts/generate_local_harness_set.py`，含 `harness_set.v1`／`wiring_contract.v1` 与 10 项测试）；**P7-A（声明核对器，D1）已完成**（每组件 9 行核对、`review_component_declarations.py` 入口、退出码即裁决、17 项测试；全仓 38 profile sweep＝32 ok／6 真实非 ok）；**P7-C（路径/输入编译，D3）实施中**；**P7-D／P7-E 完全未开始**。详见该文档 **§10 实施进展**。P7 可自动接入的形态上限仍由 P6 的已验收协议子集决定。

- [第二阶段通用 CPU／IP 声明式适配](2026-10-09-stage2-declarative-cpu-ip-adaptation.md)：保留既有架构，细化 L1–L3、基础／功能事件、三类依赖、四核五类 IP 与未知 HMAC 基础接入门禁；M0 实施中，A1/A3 已登记，真实短门禁被启动内存预算拒绝；不提升能力等级。

- [P2 Task4来源与逐边证据](2026-10-06-source-provenance-task4.md)：来源/见证、真实RVFI退休和UART帧已接入；完整寄存器/FIFO/IRQ因果仍待验收。

- [P2 运行路径契约实施](2026-10-06-runtime-path-contract-implementation.md)：有边身份的路径、显式节点映射、静态预检、新 decoder 与真实逐边证据；实施中，不替代总计划验收。

- [持续状态与多组件场景实施基线](2026-09-27-persistent-multicomponent-fuzz-implementation.md)：内存、事务、reset、IRQ、replay 的详细验收编号；其中早期外设范围与完成状态按当前总计划重新解释。
- [生成式本地运行时](2026-10-04-generated-local-runtime.md)、[生成式本地模板契约](2026-10-04-local-template-contract-registry.md)、[源码锁门禁](2026-10-04-local-source-lock-gate.md)：生成单组件 harness 的分项实施记录。
- [在线持续批次](2026-10-05-online-stateful-scenario-batches.md)：同一 testcase 连续输入的已有实现与受限范围。
- [仓库清理记录](2026-10-06-current-design-repository-cleanup.md)：已移出文件和保留引用的依据。

## 定向组合计划

2026-10-05 的 `ibex-*`、`cv32e40p-*`、`cva6-*` 和 `picorv32-*` 计划只描述各自锁定的 CPU/IP 组合与源码身份。它们是当前能力的实施历史，不能合并成“任意同协议组件自动接入”的验收。

## 历史目标计划

2026-07 至 2026-09 的 `*soc*`、`*composition*`、`*scheme*` 计划，以及 [2026-09-14 SoC 生成总计划](2026-09-14-soc-composition-and-fuzz.md)，记录完整总线/互连生成和早期 RFuzz 对照路线。这些文件留在原路径以维持交叉引用和证据检索，不再决定当前工作的完成标准。

判定某任务是否完成时，先找当前总计划的验收门禁，再查看对应源码身份的真实 RTL 报告；计划中的“通过”文字本身不是当前工作树的运行证据。
