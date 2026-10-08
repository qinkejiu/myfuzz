# P4 在线路径先行选源与候选身份（2026-10-07）

## 范围与实现

`OnlineCaseDecoder` 现在预编译已声明的路径候选。每例先排除因指令空间耗尽而不可执行的路径，再用调用方提供的逐源 `coverage_hints` 给路径赋权，最后只在选定路径的合法源中解释直接 source 字节或做加权选择。路径权重取其当前合法源的最大权重，避免仅因路径拥有更多源就自动获益。选择器只读取输入的前 8 字节，保持每例解码成本受限。

启用 `RuntimePathContract` 时，可显式传入覆盖所有目标的 `flow_by_target={target_id: "F1"…"F6"}`。这产生 `online_case_decoder.v3` manifest，并由 `decision_metadata(case)` 返回 `case_id/direction/flow_id/path_id/target_id/source_id`；其中 `path_id` 是声明图的稳定边路径身份。旧 v1/v2 manifest 与 `OnlineCase` 编码保持原样；旧配置的 `flow_id` 为 `None`，不从路径名称猜测类别。v3 manifest 的 flow 声明随 decoder 文档进入原有身份与 replay 机制。

## 测试证据

测试先验证原行为失败：直接 source 字节能越过目标路径，且改变反馈权重不能改变目标路径。随后实现并执行：

```text
PYTHONPATH=src pytest -q tests/scenario/test_online_path_first_selection.py tests/scenario/test_edge_aware_decoders.py tests/scenario/test_online_session_partial_replay.py tests/scenario/test_online_uart_source_events.py tests/integration/test_scenario_rfuzz_terminal_identity.py tests/integration/test_rfuzz_runtime_path_preflight.py
63 passed, 9 subtests passed in 1.11s
```

聚焦用例覆盖跨路径直接字节、反馈改选路径、大权重多字节熵、单路径兼容、运行时 OR 路径、v3 flow 身份重建和非法声明拒绝。上述测试是解码器与局部集成证据，不是 RTL 搜索或 P4 阶段验收。

## 尚需集成

在线 RFuzz executor 已调用 `decision_metadata(case)`，在每个 `online_decisions` 行中记录 `direction/flow_id/path_id/target_id/source_id`。局部集成 fixture 的 v3 decoder 已经通过在线 transport 身份校验和完整前缀 fresh replay。

真实 Ibex＋双 PULP GPIO 与 Ibex＋UART decoder 工厂已传入受信 `flow_by_target`：CPU 发起的 GPIO MMIO→回环与 UART TX 归 F4，GPIO 外部 pin→IRQ→ISR 和 UART RX→IRQ→CPU 归 F5。这是每个链的**主要变异目标**；其中发生的后续 F2 读取仍须按真实事件另行计证，不把一个标签当成整条链已完成。两个工厂现在生成 v3 decoder manifest。PULP v3 manifest 经 `OnlineCaseDecoder.from_document` 重建后，对两个候选字节的 case 与元数据逐项一致；UART 子类的自定义调度通过两次独立工厂构建的 manifest 与决策身份一致性核对。

附加工厂/契约定向测试：

```text
PYTHONPATH=src pytest -q tests/integration/test_runtime_fixture_contracts.py tests/scenario/test_online_real_flow_mapping.py tests/scenario/test_online_path_first_selection.py
20 passed in 19.30s
```

真实 RTL 搜索是否由路径阶段反馈改变后续选源、双侧目标覆盖、受控错误及长跑仍须独立验收；局部 fixture 与静态工厂身份检查不能替代这些门禁。

## 交互特征改变下一例选择

在线 executor 现在用 `_credit_online_interactions` 将新出现、且 witness event ID 与已验证源事务相交的真实交互边/路径特征计入源增益，并将本次 `interaction_source_gains` 记入决策行。增益经现有 `_online_weights()` 进入下一例路径权重；延迟反馈摘要前保留见证，摘要完成后只消费一次。覆盖目标未命中或任意事件 ID 增长本身不能冒充新交互边。

确定性测试使用 `InteractionFeedback` 从带 CPU MMIO acceptance/delivery 身份的事件序列生成 `mmio_write_delivered:cpu:gpio_a` 新边特征，再与 CPU 指令源的事务见证 ID 对齐。两条已声明的 PULP 路径在初始权重 40/40 时，同一输入选择外部 pin 路径；新边增益提高 CPU 源权重后，同一输入选择 CPU 发起路径，另一源权重不变。测试对接的是语义事件收集器与在线权重/解码器，未启动真实 RTL。

```text
PYTHONPATH=src pytest -q tests/integration/test_scenario_online_credit.py tests/scenario/test_online_path_first_selection.py tests/scenario/test_online_real_flow_mapping.py tests/integration/test_rfuzz_runtime_path_preflight.py tests/integration/test_scenario_rfuzz_terminal_identity.py
60 passed, 7 subtests passed in 0.79s
```

真实 RTL 门禁仍未通过：须在冻结源码身份的 Ibex＋PULP GPIO 和异构 UART 会话中证明新特征的 witness 确由真实输出/事务产生、实际下一例决策改变、保存的候选/完整前缀 fresh replay 一致，并与固定预算对照一起报告有效例与完整链吞吐。
