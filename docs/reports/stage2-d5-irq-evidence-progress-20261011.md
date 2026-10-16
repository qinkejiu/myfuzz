# D5 IRQ 范围分类进度（2026-10-11）

D5 实施中。本步将既有 native UART watermark／Ibex receipt 路径的 IRQ delivery、acceptance 和精确 serial retirement 分别接入 D1 历史台账及既有统一 ingest。只覆盖明确配置的 `native_uart_ibex_irq.v1` provider；未知 IP 的功能与 IRQ 原因不因此获得认证。

`UartNativeIrqJoin` 新增默认关闭的 `enable_boundary_evidence`。在既有 source output→精确 binding delivery→实际 CPU input sample 校验后，可从独立一次性队列导出 `irq_delivery`；只有精确 sample_ref、receipt、command scope、take_key 和未屏蔽的实测接受条件都成立，才导出 `irq_acceptance`。两者不依赖 UART FIFO source-cause certificate，来源仍为 unknown；不修改默认 consume 返回值或旧原因链。

`IrqDependencyEvidenceConsumer` 复用上述 join 与 `IrqSerialCertificates`。它只喂紧凑原始 tick/update/delivery/sample/take/reset 观察，忽略外部 accepted 功能证书。退休要求非零 decision／retirement serial 精确匹配，以及 serial 的 take_identity_event_id／take_key／epoch 精确对应本消费者独立认证的 native acceptance。sample 与 take 同一 receipt 的 serial 观察必须一致。缺 delivery／sample／take、屏蔽、跨 epoch、serial mismatch 或仅事件相邻均不能补齐后续 scope。

三类 D1 verified 记录分别保留 `irq_delivery`／`irq_acceptance`／`cpu_retirement`，validity 均为 historical。退休范围仍限于“已经认证的 native 接受到相同硬件 serial 的 interrupt retirement”，不证明 ISR 效果、CPU operand、IP source cause 或完整传播链。报告分三类计数，并明确 `grants_prerequisites=false`。

状态有界：pending／摘要／历史记录有独立预算；已过期的 source/delivery/sample 引用不能续证；未用注释不进入原生缓存；投影文本、树和字节数、一次性边界队列详情均有限。历史容量不足拒绝追加；journal 缺号、同 ID 改内容等完整性失败永久停止新证，历史前缀保留。

只读复核发现真实 Runner `reset_barrier` 曾被降为仅 ID，导致旧 pending native／serial 续授退休。新增两个负例先失败后修复：barrier 清除 pending acceptance 并保留 serial reset 语义，阻止旧 sample/take 继续授证。新证明要求严格推进的物理 reset receipts；支持 Runner 实际顺序中紧邻 barrier 前已经验证且未被后续组件活动消耗的 reset markers。reset before／after barrier 的新 epoch 正例均通过。

测试驱动记录：边界出口两项先失败、分类消费者初始 12 项先失败、统一 ingest 两项先失败；source/delivery 过期、sample/take serial 冲突、Runner barrier 两项和边界队列过长 receipt 文本均先 RED 后 GREEN。最终新增 **21 项 IRQ 分类＋3 项边界出口检查**；与 native-taken 合并 **36 passed（0.49 秒）**。初版扩大回归 **296 passed（17.67 秒）**。全部软件 fixture／旧消费者复算，无新增 RTL 或 fresh replay。

最终只读复核 reset 增量 **70 passed**，barrier P1 已解决，未发现新的 reset marker／epoch floor 复活路径。该复核先于最后边界队列文本硬限补正；其最终定向见上述 36 项。

尚未完成 D5：生产 Runner 的多消费者可信 token 分发、persistent prerequisite 的真实来源接入；D6 active witness 生命周期也未完成。RAM 部分见 [RAM 证据报告](stage2-d5-memory-evidence-progress-20261011.md)。不能把本步历史 IRQ 证书用作 RAM、寄存器或其他 active prerequisite。

最终验证：包含所有边界补正的兼容回归 **297 passed（17.52 秒）**，覆盖 native IRQ／serial、Runner 软件回执、RAM 新入口、D1、D3 protocol、D4 能力／派生和 legacy edge。最后队列详情补正经独立只读复核 **36 passed**，不改变默认关闭路径或增加证明 scope。`git diff --check` 通过。D5 仍保持未勾选。
