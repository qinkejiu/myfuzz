# 当前目标：独立 Harness 上的多组件数据流 Fuzz

## 目标

系统由总控环境初始化所选 CPU 和 IP 的独立 harness。每个 DUT 保留自己的真实 RTL、原生接口、局部协议和局部时序；总控层依据数据流目标、绑定关系和状态依赖，协调 harness 连续执行。一次测试会话只初始化和启动一次，随后持续接纳有独立身份的 testcase，直到发现 bug、达到明确预算或用户结束。

**数据流目标**说明本轮要探索什么，例如文档中的取指、MMIO 或中断流；它用于选择依赖路径及上游可变源，并不划定 testcase 的执行边界。**testcase** 是向当前会话提交的一次有身份的上游输入及其观察过程，例如为 CPU 的未来合法取指位置提供一条 RISC-V 指令，或给外设提供一次外部事件。一个 testcase 可以运行多个局部周期；它产生的事务、状态和 pending event 可以在后续 testcase 中继续传播。CPU 发起真实取指请求后，内存 harness 按地址和握手返回已保存的指令；访问 RAM、MMIO 或 IP 的后续动作仍由真实 RTL 执行。

多个 testcase 可以共同推进文档中的一条流，也可以把多条流连接成有序链，例如：

```text
CPU 配置 GPIO
→ 外部引脚边沿
→ GPIO RTL 更新状态并产生 IRQ
→ CPU 进入 ISR 并读取 GPIO 状态
→ CPU 把结果写入持久 RAM 或另一个 IP
```

步骤跨多个局部周期运行。普通 testcase 边界不 reset、不重装程序镜像，也不要求所有事务已结束；RAM、DUT 寄存器、事务账本、pending event 和场景状态跨 testcase 保持。只有显式 reset 或测试会话结束才按策略清理。发现 bug 时停止接纳新 testcase，并保存包含前面所有输入的会话前缀供 fresh replay。

## 原始文档的数据流范围

`SoC内部数据流动与去向.docx` 列出六类流，均纳入最终目标：F1 程序存储器→CPU 取指；F2 RAM/外设→CPU 数据读；F3 CPU→RAM 数据写；F4 CPU→外设 MMIO 控制；F5 外设 IRQ→CPU trap/ISR 后再次 MMIO；F6 CPU 配置 DMA→真实 DMA 主设备搬运 RAM/IP 数据→完成 IRQ→CPU。具体输入归属、抽象转发和每类当前实现状态见[当前实施计划](superpowers/plans/2026-10-06-current-dataflow-fuzz-implementation-plan.md)。

文档中的 Bus/Interconnect 与 Interrupt Controller 是典型 SoC 的物理结构示意。本系统用事务级 Router 与事件交付表达 F1～F6 的因果关系，不把它们实例化为一颗具体 SoC。F6 必须由真实 DMA RTL 发出主设备读写请求；当前尚无这条链的实现或验收证据。

## 输入来源和数据约束

- **Fuzzable Source**：没有真实上游 DUT 绑定的环境输入，例如 CPU 的程序镜像、未绑定的 GPIO pin、UART RX 字节或 SPI peer 响应。Fuzzer 可以按对应 ISA、协议和源范围约束它们。
- **Bound Input**：已由其他 RTL 输出或持久状态决定的输入，例如 IP 的实际 IRQ、GPIO A 到 GPIO B 的绑定值、真实 IP read response、已有 RAM 字节。Router 交付其来源值，Fuzzer 不得重新覆盖。
- **真实输出**：CPU/IP 事务、状态、数据和 IRQ 必须由真实 RTL 产生。Dependency Scheduler 只安排满足前置条件的下一步，不制造 DUT 结果。
- **持久内存**：CPU Store 根据真实地址、wdata 和 byte-enable 更新 RAM；后续 Load 读取更新后的内容。未初始化位置可以在首次读取时获得 Fuzzer 初值，之后保持到真实写入覆盖。

输入生成分三层：① 从 F1～F6 选覆盖目标与 Dependency Path；② 沿路径反向选择当前可控的 Fuzzable Source，并按 CPU 已启用的 RISC-V 指令集、IP 原生协议及组件 profile 生成合法变异；③ 根据协议握手、数据来源、当前状态和跨组件因果检查接纳时机。外设文档提供字段语义，但实际可变范围须由版本化机器可读 profile/接口事实核对；寄存器若由 CPU MMIO 配置，就通过 CPU 输入变异，不能同时随机写该 IP 寄存器。一个 testcase 默认提交一个主要上游动作；路径需要的关联环境输入必须分别声明来源与合法触发，不得随机填补真实下游结果。

数据流目标可以跨 testcase 继续：第 N 例留下的配置、RAM 写入或 IRQ 可以在第 N+1 例被消费。case 完成只划定输入与增量反馈的记账范围，不强迫 RTL 静止。当前状态参与可变源选择；已经取指、真实 Store 写入或首次读物化的字节不能被后续变异覆盖。

## 总控和执行层

```text
Session：初始化一次已登记的 CPU/IP harness 与持久状态
  → 选择数据流目标 / Dependency Path / 上游 Fuzzable Source
  → Testcase N：接纳一个主要源动作，运行多个局部周期
  → 真实 RTL 输出经 Dataflow Router 进入绑定目标
  → Dependency Scheduler 按当前协议、状态和因果条件推进
  → 保存第 N 例的状态摘要、覆盖增量与 checker 结果
  → Testcase N+1：沿用同一 RTL、RAM、事务和 pending event
  → 发现 bug 时停止输入并从会话初态重放完整前缀
```

组件的本地 cycle/tick 用于遵守该 DUT 的握手与时序。跨组件关系按事件因果和数据依赖表达，不声称全局 cycle-accurate SoC 时序，也不要求把 DUT RTL 拼成一颗具体 SoC。

## Fuzz 反馈

Fuzzer 根据已声明或插桩得到的覆盖反馈选择下一数据流目标，再沿依赖图反向选择**当前状态下**可控的上游源；变异操作按 ISA、协议与字段归属生成合法输入。每个 testcase 得到增量反馈后，反馈影响同一会话中的后续 testcase。新增覆盖或断言失败须保存包含该例在内的会话前缀；后续单例不能脱离前缀从空白初态独立重放。

Fuzz 热路径要求一次构建/初始化后连续供给案例，复用已编译路径和输入约束，以新事件游标更新反馈，普通例只返回紧凑回执；完整可重放的输入/调度/首次物化日志持续追加，在 finding 或新增覆盖时整理详细证据。性能按有效例/s、完整真实传播链/s 和每例延迟衡量，不能通过减少真实 RTL 步进、跳过 Bound Input 检查或丢弃异常输出来提高数字。

## 当前实现边界

交付按三步推进：① Ibex＋双 PULP GPIO 和至少一种不同外设先实现大部分核心功能，包括 F1～F5 中选定路径的双向合法变异、长期会话、状态/依赖、覆盖引导、断言报错、完整前缀保存与 fresh replay；此时允许 profile/路径/断言针对选定组件声明，通用范围较窄。② 同一完整框架扩展到多协议固定 CPU/IP 实例。③ 对已验收协议子集和具备受信 profile 的新组件，自动生成可微调的独立 harness、路径/输入约束并执行测试。真实 DMA 主设备的 F6 搬运流另作最终数据流验收；三步当前进度见[实施计划](superpowers/plans/2026-10-06-current-dataflow-fuzz-implementation-plan.md)。

- `ScenarioRunner`、Genome、Router、Scheduler、持久内存和真实 RTL sessions 已支撑多个固定 CPU/IP profile 的跨周期场景；支持哪些组合以[本地 Harness 运行状态](LOCAL_HARNESS_RUNTIME.md)为准。
- 当前大多数跨组件路径、source ownership、target、checker 和 harness tuning 仍由 profile/factory 显式配置。给出任意 CPU/IP 清单或本 Word 文档后自动推导全部连接和 testcase，尚未完成。
- 当前已有指令镜像变异和多条指令组成的真实 CPU 程序；“一条 RISC-V 指令作为标准 testcase”、自动建立其架构前置状态并对所有 CPU 共用，尚未成为通用入口。
- `ScenarioBatchRecorder` 能在一个 Runner 中在线提交多个 source 事件，但目前整段 batch 仍按一个 testcase 记账；`ScenarioRfuzzExecutor` 对每个 RFuzz slot 新建 Runner。跨多个独立 testcase 的一次初始化、逐例反馈与状态延续尚未实现。
- RFuzz 与场景反馈已在受限 profile 中接通；语义目标反馈、插桩 RTL branch coverage 和多组件 dependency-aware mutation 仍须按具体集成报告判断，不能互相代称。
- DMA 多主访问、任意 PLIC 行为和完整物理 SoC 时序不属于已普遍验收的能力。

## 当前入口

- [真实 CPU/IP Harness 与场景运行边界](LOCAL_HARNESS_RUNTIME.md)
- [独立 Harness 扩展设计](superpowers/specs/2026-10-04-generated-local-harness-five-protocol-design.md)
- [持续多组件 Fuzz 设计](superpowers/specs/2026-09-27-persistent-multicomponent-fuzz-design.md)
- [阶段验收报告](reports/persistent-scenario-acceptance-20260927.md)
- [当前实施计划](superpowers/plans/2026-10-06-current-dataflow-fuzz-implementation-plan.md)
- [代码组织与入口](CODE_ORGANIZATION.md)
- [当前仓库整理计划](superpowers/plans/2026-10-06-current-design-repository-cleanup.md)

`PROJECT_GOALS.md`、`configs/soc/`、`soc_builder` 及其报告记录了另一条历史 SoC 自动组合路线。除被独立 Harness 明确复用的源码事实和协议工具外，它们不定义本项目当前主目标。
