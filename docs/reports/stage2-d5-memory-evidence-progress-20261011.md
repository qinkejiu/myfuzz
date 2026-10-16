# D5 RAM writer／read snapshot 分类进度（2026-10-11）

D5 实施中。本步把实际 host MemoryService callback 的 writer→读快照字节关系接入 D1 declared／verified 台账和既有 `EdgeProvenanceConsumer.ingest`，没有给 D5 勾选完成。

`MemoryDependencyEvidenceConsumer` 复用已有 `MemoryCommitAuthority`／`MemoryReadAuthority`：要求两者绑定同一组实际 service／ledger／memory 对象，用一次性 private token 认证 journal 投影与实际发行记录完全相符。提交的启用字节保留 component、memory_id、generation、byte_offset、version、完整 writer TransactionKey 和值；读快照逐 lane 精确匹配上述身份及实际返回值。部分写只证明有实际 writer 的 lane，其他 lane 保留 incomplete，不能凭相同值补齐来源。

台账 scope 为 `memory_byte_version`、validity 为 `historical`，证书明确 `modeled_host_persistent_memory` 和 `source_origin=unknown`。这只证明建模 host RAM 字节版本进入实际读快照，不授 CPU request／retirement、CPU operand 或 IP 来源，也不授 active prerequisite。snapshot 无原生公共 IP base 投影，引用真实 writer／read journal ID、实际 commit ID 和 runtime contract 身份，不伪造 base event。

入口默认未配置，只有 startup 的 `configure_memory_events` 才安装该消费者；旧统一 ingest、报告和返回值保持兼容。私有 token 以显式参数传入，限制一次 ingest 一个事件，不写入 journal；批次错误在 token 消耗前拒绝。它是 RAM 消费者独占的 authority token 出口：现有 UART join 等不能重复消费同一 token。生产 Runner 的多消费者 token 分发尚未衔接，不因本软件入口授予生产运行能力。

状态有界：writer 版本、journal 摘要及历史记录分别限制；writer 淘汰／过期不凭同值重建；D1 历史容量不足拒绝追加、保留 incomplete，不静默删掉已认证历史。journal 缺号、冲突、旧 ID、错误 token 或与实际发行不符的投影永久阻止后续证明，已有历史证书仍保留。失败后仍消费调用者交给它的一次性 token，避免 producer 无限重复 drain。

测试驱动记录：12 项初始检查因消费者尚不存在而失败；实现后通过。统一 ingest 两项检查先因接口不存在失败，接入后通过。扩展到 **25 项定向检查通过（0.11 秒）**，覆盖实际 commit／read callbacks、混合 writer 的部分覆盖、冷 memory generation、不观测提交、篡改快照、缺 token、同值新版本、重复／冲突／缺号、淘汰／过期、历史容量、detached report、参数边界、不同实际 services 和 token 批次拒绝。全部为软件执行，无 RTL 或 fresh replay。

待完成：IRQ delivery／acceptance／retirement 分别衔接到 D1；生产 Runner 的可信 token 分发与实际 persistent prerequisite 接入；D6 active／history 生命周期。之前发现的 malformed overwrite 后旧 prerequisite 未失效仍是待办，不能用本步历史证书宣称解决。首步见 [RAM prerequisite 校验](stage2-d5-ram-witness-progress-20261011.md)。

只读复核补正：实际 authorities 接受的事务字符串没有本消费者的长度限制，新增 writer／reader 两项真实 callback 负例先失败后修复。事务各文本字段限定 512 字符，writer 引用限定 4096，component／memory 名称限定 256，总 installed resources 限定 256。另一项多 region／max_records=1 检查先因声明容量误用失败，现将 installed declarations 与历史证书预算分开；证书仍按 max_records 硬限拒绝。最终定向 **28 passed（0.10 秒）**。初版扩大兼容回归 **302 passed、18 subtests passed（17.71 秒）**；最终边界修复后的扩大兼容回归 **305 passed、18 subtests passed（18.06 秒）**，覆盖实际 MemoryService／PersistentMemory、authority、source action gate／dynamic binder、D1、D4、legacy edge 和 UART RAM joins。`git diff --check` 通过。

最终只读复核：独立定向 **34 passed**，上述两项 P2 已解决，未发现新增误授或明显误拒；结论仅覆盖 RAM 第二步，不代表 D5 整体完成。

后续衔接更新：IRQ 三个历史 scope 已按软件范围接入，见 [IRQ 证据报告](stage2-d5-irq-evidence-progress-20261011.md)。生产可信分发与 active prerequisites 仍未完成。
