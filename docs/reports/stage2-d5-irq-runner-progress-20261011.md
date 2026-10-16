# D5 IRQ Runner 入口进度

ScenarioRunner 增加默认关闭的 configure_irq_dependency_evidence 启动接口。必须已配置 provenance、安装 native UART／CPU receipt 会话，并具有精确 UART RX watermark → CPU irq 的一位绑定；不满足条件时拒绝安装。消费者使用 Runner 自己的 ownership／admission registry，固定 native_uart_ibex_irq.v1 provider，不推断未知外设原因。

普通 append 和 append_unchecked 共用 _consume_dependency_event，同步送入 RAM 与 IRQ 历史消费者。IRQ 配置的源、目标、runtime 摘要、provider 和预算进入 identity_document；默认运行身份保持原样。irq_dependency_evidence_report 返回独立 detached 历史报告。没有将已接受的历史证书作为实际 raw 事件，三种范围仍分别是 irq_delivery、irq_acceptance、cpu_retirement；不授 IRQ 原因、ISR 效果或 active prerequisite。

新增 12 项软件检查：普通日志／流式 EventJournal、默认关闭、启动一次与身份、缺实际 provider／精确 binding 拒绝、unchecked reset_barrier、journal gap、Runner 实际 native resource 路由与 CPU sample 引用补全，以及 RAM／IRQ 两种启动顺序下完整日志共存。actual routing 检查通过 _route_observed_outputs 与 _append_external_events，不凭手写 accepted 证书授范围。底层 receipt 是软件 fixture，未运行 RTL，不构成 DUT 授级。

联合 IRQ／RAM Runner、native／serial 消费者定向 **115 passed（4.74 秒）**。最终扩大兼容回归 **272 passed、4 subtests passed（12.75 秒）**，覆盖原生 IRQ binding／sample／take、serial、RAM authority／readback、旧 Runner、日志、连续会话、来源和 replay 预检。独立只读复核 **55 passed**，未发现重要缺陷。

D5 保持未勾选。RAM／IRQ 的 Runner 历史入口已接通；真实 persistent prerequisite 接入和 D6 history／active 生命周期尚未实现。Stage 2 实际命令、真实 CPU/IP／HMAC 门禁仍待计划后续部分。

后续更新：可信 RAM 前置状态已接入 Runner／Session，详见 [可信 gate 报告](stage2-d5-live-memory-prerequisites-progress-20261011.md)；在线 factory／默认 slot gate 组合和 D6 通用生命周期仍待完成。
