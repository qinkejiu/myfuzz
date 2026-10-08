# P3 受限 host RAM 低字节来源再读取

日期：2026-10-07。本文保留软件实现时的证据范围：当时两个模块 `MemoryReadAuthority` 和 `UartMemoryReadbackJoin` 尚未接入真实 CPU session/Runner。之后的接线、受控 ISR 和冻结源码 RTL 门禁见[读回真实短门禁](current-dataflow-p3-host-ram-readback-real-gate-20261007.md)；P3 整阶段仍未验收。

## 证据边界

`MemoryReadAuthority.read` 是唯一发行入口。它对实际安装的 `MemoryService` 发起 read callback，在返回 CPU 前核对完整六字段 TransactionKey、ledger 的同一 `ReadSnapshot` 对象、read payload、service callback `memory_read` 事件、实际 memory span、4 字节值、每字节版本和 writer ID；发行有界一次性 token。调用者不能用 detached `data_response.snapshot`、手工 ledger receipt 或保存的 `accepted` 标签补发行。

`UartMemoryReadbackJoin` 私有运行当前 `UartStoreMemoryJoin`，因此 Store 来源仍须由完整原始 UART/CPU 路径与实际已安装 write commit token 重建。它另行运行退休匹配器，只支持普通 RV32 `lw`：相同 data fullkey、非 trap/非 capability/非 RF 抑制、4 字节有序读响应、真实 read token、完整冻结 snapshot 与退休值一致。只有读回的 lane0 `STORE` writer ID、generation、byte offset、版本、值与先前 UART Store 证书完全一致才出 `uart_host_ram_low_byte_retired_load_readback`。高24位、整字来源、RTL RAM、一般 ISR 和后续寄存器传播均未知。

已保存的 48,323 事件 UART 记录里未找到 0x20000/0x20004 的后续 host RAM `memory_read`，且该运行早于新 read issuance。它不能证明 readback。

## 软件验证

测试先出现缺模块的 RED；实现后：

```text
PYTHONPATH=src pytest -q tests/scenario/test_uart_memory_readback.py tests/scenario/test_memory_read_authority.py
9 passed in 0.62s
```

测试覆盖实际 callback 发证、同值后写不改变旧快照版本、脱离 live token 的伪造记录、精确 writer 版本变动、缺失 writer 时 unknown 且不触发全局屏障、发行容量在 effect 前拒绝、重复 key 不重复发行。模拟 raw load 标注与 UART 来源不同的 logical case，证书分别保留 source case 和 load observed case；该 case 标签仅为观察元数据，不作为来源授权。fixture 为 actual-shaped 软件模型，不是 RTL。与当前 Store join / commit authority 组合的较宽软件复验为 **79 passed，3.68s**。

## 需要接入的真实路径

1. 在目标 CPU session 创建与实际 service 绑定的 `MemoryReadAuthority`，开启 `include_writer_kinds`；仅 data RAM read 的 `_serve` 分支改用 `read_authority.read(component, self.service, key, beat_address, width_bytes=4)`。instruction fetch 可沿用原调用。read authority 必须在 CPU response 前冻结真实 callback；Runner 不能稍后从 detached service event 自行补授权。
2. Runner 按发行顺序 drain 其私有 token，追加 `memory_read_issuance` 审计事件，并将 token 仅作为进程内参数送给 `UartMemoryReadbackJoin.consume`；原始 UART/CPU 事实和真实 write commit token也需依次送达。保存 trace 只包含审计事件，token 本身不可作为可重放授权。fresh replay 应由新 session 再次发行同样语义的 token。
3. 加入新模块和接线至 Runner host、online session、fresh runtime source identity；冻结源码执行受控真实在线 `lw` readback，核对跨 logical testcase 的保存事实、raw 重构负例与完整 fresh replay。

当前在线 CPU 用固定的 stream `testcase_id` 保持 data sequence 单调；跨 logical testcase 由 source admission/观测 case 区分。若改变 TransactionKey 的 `testcase_id`，ledger 会将其视为新 channel 并重启 sequence，和当前退休匹配器对连续 CPU scope 的顺序约束不兼容。真实跨 case 门禁应保留固定 CPU stream key，并验证 source case 确实推进。

本受限实现尚不保留“退休 load 先于迟到 Store 来源证书”的候选；该顺序当前给 unknown。长期 distinct writer 历史受 `max_writer_versions=256` 约束，满额触发 certainty barrier；需要在长跑中测量并设计有证据的回收策略。
