# D5 Runner 实际 RAM 凭据衔接

## 已完成范围

ScenarioRunner 新增默认关闭的 configure_memory_dependency_evidence 启动入口；仅接收实际 MemoryService、启用 commit stream 与 readback 的会话。现有 provenance 启动创建的实际 write/read authorities 被复用；无旧 UART join 时安装相同实际服务的 authorities。注册 dependency_evidence 独立一次性 view，旧消费者保留 default view，未安装旧消费者时及时退休 default。配置的运行契约摘要、组件和各项预算进入 Runner identity_document，默认身份不增加字段。

_EventLog 的普通 append 与容量屏障 append_unchecked 均同步送入同一个历史消费者，保证其看到完整连续 journal。实际 commit 在 producer ack 前 lookup 精确 receipt 并 stage；实际 read 由 GeneratedCve2Session._serve 调用安装的 read authority，Runner drain 时同步分发私有 token。token 不写入 journal，不从保存的 accepted 文档恢复，也不为新消费者重复调用实际 read/write。报告通过 memory_dependency_evidence_report 独立查询，仅授历史 host 字节版本 scope。

## 修复与验证

新增 14 项 Runner 软件检查，覆盖普通日志／流式 EventJournal、实际 CPU _serve 回调、旧 UART readback／store／RAM join 共存、默认关闭与启动身份、配置失败及保存文档拒绝。以下缺陷先由负例复现再修复：

- 配对注册第二个 authority 失败留下第一个半注册状态：新增无副作用注册预检。
- 新消费者启用后旧 RAM join 漏掉 receipt staging：保留独立的实际 stage-before-ack。
- 替换另行安装且已有实际 read issuance 的 authority：在安装前拒绝。
- 第三个消费者延迟退休导致 read token 重复入 journal：read drain 按当前 Runner 未消费的 recipient 筛选；其他消费者仍可延迟领取原始凭据。

只读复核发现并验证最后一项缺陷；修复后独立四模块 65 passed，未发现新重要问题。14 项 Runner 定向检查通过。最终扩大兼容回归 **201 passed、4 subtests passed（7.88 秒）**，涵盖 authority／RAM 历史消费者、旧 UART joins、EventJournal、连续会话、来源与 replay 预检及 IRQ 历史消费者。

本步没有运行 RTL 或 fresh replay；fixture 中的硬件身份未授任何等级。实际 MemoryService 回调证明软件生产路径，不能证明真实 DUT。

## 尚未完成

D5 保持未勾选。IRQ 历史消费者尚待接入 Runner 的统一实际事件入口；实际 persistent prerequisite 和 D6 history／active 生命周期仍待实现。Stage 2 生产命令／验收矩阵亦未完成，本启动 API 不代表新 CPU/IP 或 HMAC 门禁通过。

后续更新：IRQ Runner 历史入口现已衔接，详见 [IRQ Runner 报告](stage2-d5-irq-runner-progress-20261011.md)。可信 persistent 前置状态与 D6 生命周期仍待完成。

后续更新：可信 RAM 前置状态已接入 Runner／Session，详见 [可信 gate 报告](stage2-d5-live-memory-prerequisites-progress-20261011.md)；在线 factory／默认 slot gate 组合和 D6 通用生命周期仍待完成。
