# P3 在线 slot 回执重传

日期：2026-10-06。范围：RFuzz transport 已拥有的 `(buffer_id, slot, raw_hash)` 重传；不代表 P3 通用长会话验收。

以前 `ScenarioRfuzzExecutor` 能识别重复 slot 并复用 coverage，但回执 sink 失败后重传不会再次向 `on_receipt` 交付原回执，可能使已执行 RTL 的 slot 缺少持久化行。现在完成缓存同时保留原 receipt；相同原始输入的重传向 sink 补交原回执，不重复执行 RTL。相同 slot 携带不同 raw hash 仍被拒绝。在线 live 写入端按 run、buffer、slot、raw hash 去重；补交早期 slot 时根据原 slot 身份找其输入 decision，避免误取最新 slot 的输入字节。

测试先行复现了 sink 失败后的回执缺失、重复 FIFO chunk 和旧 slot 误关联新输入。定向验证：

```text
PYTHONPATH=src python3 -m unittest tests.scenario.test_rfuzz_scenario_executor tests.integration.test_scenario_rfuzz_terminal_identity tests.integration.test_scenario_rfuzz_transport tests.integration.test_scenario_online_credit -q
Ran 27 tests in 0.217s
OK
```

本轮没有新增真实 RFuzz 长会话的重传压力门禁。通用 `SourceDecision`、背压、跨 slot pending 状态、finding 后封口及完整前缀 replay 仍须按主计划单独验收。
