# Stage 2 C1–C2：组件中立基础端口事件

日期：2026-10-10。C1–C2 验收记录聚焦当时完成的事件出口和 generic target 模板；后续 C3 协议事务事件及 C4 输入／绑定／reset 事件分别见对应报告。当前剩余 C5–C7 的 checker 与覆盖工作。

## 行为

新增 `ip_base_event.v1` 投影器，从已有 `local_tick_sample` 导出 profile 声明的物理输出 `port_sample` 和实际观测值变化 `signal_change`。每条派生事件包含 IP 与实例身份、endpoint/role、raw event 引用、局部事件 ID、clock domain/tick、reset epoch、payload、观察性质及当前不可推断的 transaction/action/mapping 引用。位切片依据物理导出描述提取，输出名称只用作 profile 绑定，不推断 GPIO、UART 或其他功能语义。

新的 v2 通用 APB3、TL-UL、Wishbone artifact 写入 `base_event_schema_version`，并在 `ScenarioRunner` 的原始 tick-event 出口启用投影。正常的 `local_tick_sample` 记录及其 event ID 保持原样；投影引用该 raw event。此前生成且没有版本标记的 artifact 不生成新事件，保留原回放行为。

## 验证

三个独立 pytest 子进程并行运行：

- `tests/scenario/test_ip_base_events.py tests/scenario/test_event_journal.py`：**11 passed**。
- 通用 APB3／TL-UL／Wishbone artifact 与 session factory：**13 passed，7 subtests passed，5 skipped**。跳过的是显式真实 RTL 测试，本轮未运行这些 DUT。
- `tests/local_harness/test_runtime_renderer.py tests/local_harness/test_runtime_template_identity.py`：**18 passed，68 subtests passed**；包括现有 Verilator runtime lint 与身份回归。

回归覆盖切片值、raw 引用、原始记录不变、观察变化及 reset epoch 清空历史、缺失输出 fail closed、旧 artifact 不投影。`local_tick_sample` 仍是原始证据；投影事件不声称总线请求／接纳／响应、输入实际采样或功能完成。
