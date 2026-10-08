# 实施计划索引

## 当前唯一总计划

[当前数据流 Fuzz 实施计划](2026-10-06-current-dataflow-fuzz-implementation-plan.md)分为“最终目标功能”和“逐阶段实现情况”两部分，并逐项覆盖原始 Word 文档的取指、数据读、数据写、MMIO、中断和 DMA 六类流。需求口径以 [当前设计](../../CURRENT_DESIGN.md) 为准；具体组合的实际能力以 [运行能力表](../../LOCAL_HARNESS_RUNTIME.md) 与 [报告索引](../../reports/README.md) 为准。

## 仍适用的专题契约

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
