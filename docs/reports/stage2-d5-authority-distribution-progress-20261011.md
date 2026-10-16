# D5 实际内存凭据分发进度

本步为生产 Runner 分发准备实际 authority 接口；尚未完成 Runner 连接或实际 persistent prerequisite，D5 保持未完成。

MemoryCommitAuthority 与 MemoryReadAuthority 现在允许在首次实际 issuance 前注册消费者，最多 16 个（含既有 default），名称非空且不超过 64 字符。实际 write callback／read invocation 仍是唯一凭据入口。同一 token 每个注册消费者只能领取一次 detached view；最后一个消费者领取后释放 pending，未知消费者和重复领取不影响其他消费者。pending 上界仍按实际 issuance 计数，不因消费者数量放宽。

MemoryDependencyEvidenceConsumer 可显式选择两边均已注册的 authority_consumer。测试证明历史字节消费者先领取后，旧消费者仍能获得自己的原始凭据，读写事件数量不增加。默认配置保持原有一次性 default 领取。authority 降级后所有 view 均不输出证明，但可分别退休，避免反复 drain。

验证：新增 12 项软件检查，先观察缺失接口导致失败，再实现并通过。联合实际 authority、RAM 历史消费者、UART readback 集成与 UART store Runner 回归共 **91 passed（6.41 秒）**。独立只读复核运行四个相关模块 **80 passed**，未发现阻断缺陷。测试使用实际 MemoryService 回调，不运行 RTL，不授来源、CPU 退休或 active prerequisite。

后续：Runner 启动配置消费者、将私有 token 在实际 callback drain 时同步分发，并从统一 journal 入口持续提供事件；配置纳入运行身份。随后接入可信 persistent 前置状态与 D6 的失效生命周期。仅凭本步接口不能声称生产分发已完成。

后续更新：RAM Runner 的实际分发与启动身份已完成软件衔接，详见 [Runner 报告](stage2-d5-memory-runner-progress-20261011.md)；IRQ Runner 和实际 prerequisite 仍未完成。

后续更新：IRQ Runner 历史入口现已衔接，详见 [IRQ Runner 报告](stage2-d5-irq-runner-progress-20261011.md)。可信 persistent 前置状态与 D6 生命周期仍待完成。
