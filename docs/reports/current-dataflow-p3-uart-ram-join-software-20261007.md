# UART SW 操作数到 host RAM 低字节 writer 的受限 join

> **⚠ 复算可用性（2026-10-09 更新）**：本文引用的部分原始产物目录在 2026-10-09 的 `runs/` 清理中被删除，因此文中指向 `runs/` 的链接可能失效。**报告的结论、数字与边界仍然有效**（记录的是当时真实执行的结果），但"从原始产物复算"的能力已不存在。删除范围、已重建项与逐条断链清单见 [已删除的原始产物](DELETED_ARTIFACTS_20261009.md)。
日期：2026-10-07。P3 软件链新增 `UartRamCommitJoin`。受限 Runner 回执交接的定向软件测试已通过。后续独立源码快照曾以旧 join 完成 4/4 真实在线与 fresh replay，但迁移审查指出迟到 commit 生命周期缺口；当前主接线已改用 `UartStoreMemoryJoin`，其[新冻结源码真实门禁](current-dataflow-p3-store-real-gate-20261007.md)另行记录。P3 整阶段仍未验收。

## 证书边界

模块独立消费原始 UART/CPU 事实，以 `UartOperandUseTracker` 重建确切寄存器版本的 SW rs2 读取，以 `CpuRetirementMatcher` 重建同一 SW 的指令与有序 data accept/response。它不接受保存 trace 中的 `accepted` use/match 标签作为授权。另一个输入只来自实际安装、尚未 ack 的 `MemoryService` 成功 callback：`MemoryCommitAuthority.stage` 通过实际 service/ledger/receipt 对象身份锁定提交，`UartRamCommitJoin.stage_commit` 立即 pin 其凭据。

受限 join 要求同一六字段 data TransactionKey、同一 CPU scope/退休 order/指令、SW 全字地址、mask15 和 operand 值。成功提交的 payload 摘要必须对应这一地址/值/宽度/BE，`resolve_span` 的 region/offset 与冻结凭据一致，四个 enabled STORE cells 必须逐字节等于被退休 SW 消费的 word。只有 lane0 的 writer 版本获得 UART 低8位来源证书；高24位来源、RTL RAM、后续 RAM load 和一般 ISR 均为 unknown。受限证书 `proof_scope=uart_seed_operand_host_ram_byte_writer`，RAM 类型明确为 `modeled_host_persistent_memory`。

join 使用有界 pending 容量。普通无关 SW 退休会释放相应 commit，不保留所有历史退休；迟到的 UART seed 可以补齐同一历史退休的匹配。CPU reset/flush 清除待匹配事实。缺失或矛盾原始证据 fail closed，容量超限进入 barrier。它不把较晚的同值写回当作旧 writer 版本。

## 软件验证与真实记录限制

测试先看到缺模块的 RED，之后运行：

```text
PYTHONPATH=src pytest -q tests/scenario/test_uart_ram_commit_join.py tests/scenario/test_memory_commit_authority.py tests/scenario/test_uart_operand_use.py
76 passed in 4.49s
```

新增测试覆盖实际 callback 的低字节版本、不同值提交、伪造标签与 ack 后旧 receipt、迟到 seed 的历史退休匹配。测试用 actual-shaped 软件事实和真正 `MemoryService`/`TransactionLedger` 回调；这不代替 RTL。

后续新增的 Runner 接口测试命令：

```text
PYTHONPATH=src pytest -q tests/scenario/test_uart_ram_commit_runner.py
4 passed in 0.44s
```

它检查实际 callback 在 ack 前交付 join、保存一条 commit/低字节证书、已 ack 的 detached 伪造记录不出证、32 个连续 callback batch 的 stream 可清空，以及 CPU/UART 原始事实的顺序转发。测试仍是模拟会话，不是新 RTL 运行。

旧 [UART operand-use 冻结记录](../../runs/current-dataflow-p3-uart-operand-use-20261006-freeze-online/) 包含4条 use 和8条旧 `memory_write`，但它生成时未启用新 commit stream，没有 `memory_write_commit` 或已安装 service 的 live issuance。因此不能从旧 trace 直接出 RAM 来源证书。对旧 trace 中全部原始 matcher 相关事件的只读重放得到 282 条非访存 accepted、18 条访存 accepted、8 条 unsupported rejected、0 条 incomplete；这只是 CPU matcher 的可用性检查，不证明 RAM join。

## Runner 接点与剩余在线门禁

Runner 当前定向接线将目标 CPU session 的 `MemoryService` 设为有界 stream（capacity256），以实际安装的 service 构造 join。`_append_external_events` 在处理 service 事件后、ack 前通过 `lookup_pending_commit(commit_id)` 取得**实际 receipt 对象**并 stage；`_append_uart_ram_commit_join` 接收原始 CPU/UART 事件，追加证书。保存的 `memory_write_commit` 是可审计事实，单靠 detached document 或旧 `memory_write` 不能 stage。上述4项聚焦测试覆盖其局部顺序。

仍需确认 Runner host、online session、fresh runtime 的 source identity 闭包，并新建冻结源码的真实在线保存运行。独立重构 raw UART use + CPU退休/请求响应 + live callback join，做凭据缺失、错 fullkey、错地址/值/BE、同值新 writer、伪造标签负例，再执行整份 trace 的 fresh replay。若 fresh replay 的服务回调次序不同，查明原因并修复，不能引用旧门禁代替。

当前模块仅为可集成的软件 join，不能据此将 P2/P3 标记完成。
